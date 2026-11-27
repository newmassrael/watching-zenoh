// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sealed command end to end: the pinned object an independent signer made, each refusal, and
//! (with `ring`) the round trip through a real key.

use core::cell::RefCell;
use std::string::String;
use std::vec::Vec;

use crate::key::tests::{pinned_point, zid_text, PINNED_ZID_TEXT};
use crate::*;

/// The x and y of the pinned key (`key::tests::PINNED_PUBLIC_KEY_PEM`).
const X_HEX: &str = "333f5ee6fc796c5e6045f76fafd5a7361c4b7557f8ef612248193043ce62dcbe";
const Y_HEX: &str = "399d08a53d08e963ec2da93d7c414249ef4a80d801d9c321d0bd6da7eb12fd38";

const NODE: Zid = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const NODE_HEX: &str = "101112131415161718191a1b1c1d1e1f";
const PEER: Zid = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const PEER_HEX: &str = "202122232425262728292a2b2c2d2e2f";

/// `"reset"` and `"close"` as CBOR text strings.
const RESET_HEX: &str = "657265736574";
const CLOSE_HEX: &str = "65636c6f7365";

/// `reset` of generation 7 for [`PEER`] at [`NODE`], counter 42, sealed by the pinned key. The
/// object was assembled by hand from `docs/command-seal.md` and its Sig_structure signed by
/// `openssl dgst -sha256 -sign`, whose DER signature was rewritten as r then s; nothing of this
/// crate made it.
const PINNED_SEALED_HEX: &str = concat!(
    "d2845853a201260ea108a101a401022001215820333f5ee6fc796c5e6045f76f",
    "afd5a7361c4b7557f8ef612248193043ce62dcbe225820399d08a53d08e963ec",
    "2da93d7c414249ef4a80d801d9c321d0bd6da7eb12fd38a0582d846572657365",
    "7450101112131415161718191a1b1c1d1e1f8250202122232425262728292a2b",
    "2c2d2e2f07182a5840b0215a5cda4b52472696d381a3f18369606b280215f91a",
    "69fa332ccd1863d87bba57a17ea7399b81b6a905335892b273e2322feee6ad4d",
    "e583c10dc3397be220",
);

/// The signature in [`PINNED_SEALED_HEX`].
const PINNED_SIGNATURE_HEX: &str = concat!(
    "b0215a5cda4b52472696d381a3f18369606b280215f91a69fa332ccd1863d87b",
    "ba57a17ea7399b81b6a905335892b273e2322feee6ad4de583c10dc3397be220",
);

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn protected_hex() -> String {
    std::format!("a201260ea108a101a401022001215820{X_HEX}225820{Y_HEX}")
}

fn payload_hex(verb: &str, generation: &str, counter: &str) -> String {
    std::format!("84{verb}50{NODE_HEX}8250{PEER_HEX}{generation}{counter}")
}

fn pinned_payload_hex() -> String {
    payload_hex(RESET_HEX, "07", "182a")
}

fn pinned_signature() -> [u8; SIGNATURE_LEN] {
    hex(PINNED_SIGNATURE_HEX).try_into().expect("64 bytes")
}

/// A COSE_Sign1 of these headers and payload, as the format writes one.
fn assemble(protected: &[u8], payload: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
    let mut out = [0u8; 512];
    let len = write_sign1(protected, payload, signature, &mut out).expect("fits");
    out[..len].to_vec()
}

/// The Sig_structure of these headers and payload.
fn to_be_signed(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 512];
    let len = write_to_be_signed(protected, payload, &mut out).expect("fits");
    out[..len].to_vec()
}

/// What a verifier was asked: the point, the message and the signature.
type Asked = (Vec<u8>, Vec<u8>, Vec<u8>);

/// A verifier that answers `answer` and records what it was asked.
struct Recording {
    answer: bool,
    asked: RefCell<Vec<Asked>>,
}

impl Recording {
    fn answering(answer: bool) -> Self {
        Self {
            answer,
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl Es256 for Recording {
    fn verify(
        &self,
        point: &[u8; POINT_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        self.asked
            .borrow_mut()
            .push((point.to_vec(), message.to_vec(), signature.to_vec()));
        self.answer
    }
}

/// A signer whose key is the pinned one and whose signature is fixed, so what [`seal`] writes
/// around it can be compared byte for byte.
struct Fixed {
    point: [u8; POINT_LEN],
    signature: Option<[u8; SIGNATURE_LEN]>,
    signed: RefCell<Vec<Vec<u8>>>,
}

impl Fixed {
    fn pinned() -> Self {
        Self {
            point: pinned_point(),
            signature: Some(pinned_signature()),
            signed: RefCell::new(Vec::new()),
        }
    }
}

impl Es256Signer for Fixed {
    fn point(&self) -> [u8; POINT_LEN] {
        self.point
    }
    fn sign(&self, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
        self.signed.borrow_mut().push(message.to_vec());
        self.signature
    }
}

fn pinned_command() -> Command {
    Command {
        verb: Verb::Reset,
        node: NODE,
        object: Object {
            peer: PEER,
            generation: Some(7),
        },
        counter: 42,
    }
}

/// Open an object of these headers and payload, signed with zeros, under a verifier that accepts
/// every signature: what the reader refuses on its own.
fn open_unsigned(protected: &str, payload: &str) -> Result<Sealed, SealError> {
    let bytes = assemble(&hex(protected), &hex(payload), &[0u8; SIGNATURE_LEN]);
    open_sealed(
        &bytes,
        &NODE,
        &mut ReplayWindow::<4>::new(),
        &Recording::answering(true),
    )
}

#[test]
fn the_test_helpers_assemble_the_pinned_object() {
    assert_eq!(
        assemble(
            &hex(&protected_hex()),
            &hex(&pinned_payload_hex()),
            &pinned_signature()
        ),
        hex(PINNED_SEALED_HEX)
    );
}

#[test]
fn the_pinned_object_opens_to_its_commander_and_its_command() {
    let verifier = Recording::answering(true);
    let mut window = ReplayWindow::<4>::new();
    let sealed = open_sealed(&hex(PINNED_SEALED_HEX), &NODE, &mut window, &verifier)
        .expect("the pinned object opens");
    assert_eq!(zid_text(&sealed.commander), PINNED_ZID_TEXT);
    assert_eq!(sealed.verb, Verb::Reset);
    assert_eq!(
        sealed.object,
        Object {
            peer: PEER,
            generation: Some(7)
        }
    );
    assert_eq!(sealed.counter, 42);
    assert_eq!(window.last(&sealed.commander), Some(42));

    let asked = verifier.asked.borrow();
    assert_eq!(asked.len(), 1);
    let (point, message, signature) = &asked[0];
    assert_eq!(point.as_slice(), pinned_point().as_slice());
    assert_eq!(
        *message,
        hex(&std::format!(
            "846a5369676e61747572653158{:02x}{}4058{:02x}{}",
            PROTECTED_LEN,
            protected_hex(),
            pinned_payload_hex().len() / 2,
            pinned_payload_hex()
        )),
        "the Sig_structure of RFC 9052, section 4.4, the bytes openssl signed"
    );
    assert_eq!(signature.as_slice(), pinned_signature().as_slice());
}

#[test]
fn seal_writes_the_pinned_object_byte_for_byte() {
    let signer = Fixed::pinned();
    let mut out = [0u8; MAX_SEALED_LEN];
    let len = seal(&pinned_command(), &signer, &mut out).expect("seals");
    assert_eq!(out[..len], hex(PINNED_SEALED_HEX)[..]);
    let signed = signer.signed.borrow();
    assert_eq!(
        signed.as_slice(),
        [to_be_signed(
            &hex(&protected_hex()),
            &hex(&pinned_payload_hex())
        )]
    );
}

#[test]
fn a_signature_that_does_not_verify_is_refused_and_takes_no_counter() {
    let mut window = ReplayWindow::<4>::new();
    assert_eq!(
        open_sealed(
            &hex(PINNED_SEALED_HEX),
            &NODE,
            &mut window,
            &Recording::answering(false)
        ),
        Err(SealError::BadSignature)
    );
    assert_eq!(window.iter().count(), 0);
}

#[test]
fn a_command_for_another_node_is_refused_before_its_signature_is_checked() {
    let verifier = Recording::answering(true);
    let mut window = ReplayWindow::<4>::new();
    assert_eq!(
        open_sealed(&hex(PINNED_SEALED_HEX), &PEER, &mut window, &verifier),
        Err(SealError::WrongNode)
    );
    assert!(verifier.asked.borrow().is_empty());
    assert_eq!(window.iter().count(), 0);
}

#[test]
fn a_verified_command_takes_no_counter_until_it_is_taken() {
    let verifier = Recording::answering(true);
    let mut window = ReplayWindow::<1>::new();
    let bytes = hex(PINNED_SEALED_HEX);
    let verified = verify_sealed(&bytes, &NODE, &verifier).expect("verifies");
    assert_eq!(verified.sealed().counter, 42);
    assert_eq!(zid_text(&verified.sealed().commander), PINNED_ZID_TEXT);
    assert_eq!(window.iter().count(), 0, "verifying took nothing");
    let again = verify_sealed(&bytes, &NODE, &verifier).expect("a replay verifies too");
    assert_eq!(verified.take(&mut window), Ok(*verified.sealed()));
    assert_eq!(again.take(&mut window), Err(SealError::Replay { last: 42 }));
}

#[test]
fn a_command_verified_and_not_taken_leaves_the_window_to_the_commanders_taken() {
    let verifier = Recording::answering(true);
    let mut window = ReplayWindow::<1>::new();
    let other: Zid = [0x77; 16];
    assert_eq!(window.accept(&other, 1), Ok(()));
    let verified = verify_sealed(&hex(PINNED_SEALED_HEX), &NODE, &verifier).expect("verifies");
    assert_eq!(verified.take(&mut window), Err(SealError::WindowFull));
    assert_eq!(window.last(&other), Some(1));
    assert_eq!(
        verify_sealed(&hex(PINNED_SEALED_HEX), &PEER, &verifier),
        Err(SealError::WrongNode)
    );
}

#[test]
fn the_same_object_twice_is_a_replay() {
    let verifier = Recording::answering(true);
    let mut window = ReplayWindow::<4>::new();
    let bytes = hex(PINNED_SEALED_HEX);
    assert!(open_sealed(&bytes, &NODE, &mut window, &verifier).is_ok());
    assert_eq!(
        open_sealed(&bytes, &NODE, &mut window, &verifier),
        Err(SealError::Replay { last: 42 })
    );
}

#[test]
fn a_head_longer_than_its_value_needs_is_refused_wherever_it_is() {
    let pinned = hex(PINNED_SEALED_HEX);
    let mut longer_array = std::vec![0xd2, 0x98, 0x04];
    longer_array.extend_from_slice(&pinned[2..]);
    assert_eq!(
        open_sealed(
            &longer_array,
            &NODE,
            &mut ReplayWindow::<4>::new(),
            &Recording::answering(true)
        ),
        Err(SealError::NonCanonical)
    );

    let protected = protected_hex().replacen("a2", "b802", 1);
    assert_eq!(
        open_unsigned(&protected, &pinned_payload_hex()),
        Err(SealError::NonCanonical)
    );
    let payload = payload_hex(RESET_HEX, "07", "19002a");
    assert_eq!(
        open_unsigned(&protected_hex(), &payload),
        Err(SealError::NonCanonical)
    );
    let payload = payload_hex(RESET_HEX, "1807", "182a");
    assert_eq!(
        open_unsigned(&protected_hex(), &payload),
        Err(SealError::NonCanonical)
    );
}

#[test]
fn an_algorithm_other_than_es256_is_refused() {
    let es384 = protected_hex().replacen("a20126", "a2013822", 1);
    assert_eq!(
        open_unsigned(&es384, &pinned_payload_hex()),
        Err(SealError::Algorithm)
    );
    let named = protected_hex().replacen("a20126", "a201654553323536", 1);
    assert_eq!(
        open_unsigned(&named, &pinned_payload_hex()),
        Err(SealError::Malformed),
        "an algorithm named by text is not the format"
    );
}

#[test]
fn a_key_that_is_not_an_uncompressed_p256_key_is_refused() {
    let p384 = protected_hex().replacen("2001", "2002", 1);
    assert_eq!(
        open_unsigned(&p384, &pinned_payload_hex()),
        Err(SealError::Key)
    );
    let okp = protected_hex().replacen("a40102", "a40101", 1);
    assert_eq!(
        open_unsigned(&okp, &pinned_payload_hex()),
        Err(SealError::Key)
    );
    let compressed = protected_hex().replacen(&std::format!("225820{Y_HEX}"), "22f5", 1);
    assert_eq!(
        open_unsigned(&compressed, &pinned_payload_hex()),
        Err(SealError::Key)
    );
    let short_x = protected_hex().replacen(
        &std::format!("5820{X_HEX}"),
        &std::format!("581f{}", &X_HEX[2..]),
        1,
    );
    assert_eq!(
        open_unsigned(&short_x, &pinned_payload_hex()),
        Err(SealError::Key)
    );
}

#[test]
fn a_header_out_of_order_or_unprotected_is_not_the_format() {
    let protected = protected_hex();
    let swapped = std::format!("a2{}0126", &protected[6..]);
    assert_eq!(
        open_unsigned(&swapped, &pinned_payload_hex()),
        Err(SealError::Malformed)
    );

    let pinned = hex(PINNED_SEALED_HEX);
    let unprotected_at = 2 + 2 + PROTECTED_LEN;
    assert_eq!(pinned[unprotected_at], 0xa0);
    let mut with_kid = pinned[..unprotected_at].to_vec();
    with_kid.extend_from_slice(&[0xa1, 0x04, 0x41, 0x00]);
    with_kid.extend_from_slice(&pinned[unprotected_at + 1..]);
    assert_eq!(
        open_sealed(
            &with_kid,
            &NODE,
            &mut ReplayWindow::<4>::new(),
            &Recording::answering(true)
        ),
        Err(SealError::Malformed)
    );
}

#[test]
fn an_object_untagged_detached_or_followed_by_bytes_is_not_the_format() {
    let pinned = hex(PINNED_SEALED_HEX);
    let open = |bytes: &[u8]| {
        open_sealed(
            bytes,
            &NODE,
            &mut ReplayWindow::<4>::new(),
            &Recording::answering(true),
        )
    };
    assert_eq!(open(&pinned[1..]), Err(SealError::Malformed), "untagged");
    let mut trailing = pinned.clone();
    trailing.push(0x00);
    assert_eq!(
        open(trailing.as_slice()),
        Err(SealError::Malformed),
        "a byte after it"
    );
    assert_eq!(open(&[]), Err(SealError::Malformed), "nothing");

    let payload_at = 2 + 2 + PROTECTED_LEN + 1;
    let payload_len = pinned_payload_hex().len() / 2;
    let mut detached = pinned[..payload_at].to_vec();
    detached.push(0xf6);
    detached.extend_from_slice(&pinned[payload_at + 2 + payload_len..]);
    assert_eq!(
        open(detached.as_slice()),
        Err(SealError::Malformed),
        "a detached payload"
    );
}

#[test]
fn a_payload_that_does_not_match_its_verb_is_not_the_format() {
    let protected = protected_hex();
    let cases = [
        (
            payload_hex(RESET_HEX, "f6", "182a"),
            "a reset with no generation",
        ),
        (
            payload_hex(CLOSE_HEX, "07", "182a"),
            "a close with a generation",
        ),
        (
            payload_hex("6468616c74", "f6", "182a"),
            "a word that is no verb",
        ),
        (payload_hex(RESET_HEX, "07", "382a"), "a negative counter"),
        (
            payload_hex(RESET_HEX, "07", "182a").replacen(
                &std::format!("50{NODE_HEX}"),
                &std::format!("4f{}", &NODE_HEX[2..]),
                1,
            ),
            "a node zid of fifteen bytes",
        ),
    ];
    for (payload, why) in cases {
        assert_eq!(
            open_unsigned(&protected, &payload),
            Err(SealError::Malformed),
            "{why}"
        );
    }
    let close = payload_hex(CLOSE_HEX, "f6", "182a");
    assert_eq!(
        open_unsigned(&protected, &close).map(|sealed| (sealed.verb, sealed.object.generation)),
        Ok((Verb::Close, None)),
        "the control: the same shape with null opens"
    );
}

#[test]
fn every_verb_seals_and_opens_with_its_word() {
    for (at, verb) in Verb::ALL.into_iter().enumerate() {
        assert_eq!(Verb::of_word(verb.word().as_bytes()), Some(verb));
        let command = Command {
            verb,
            node: NODE,
            object: Object {
                peer: PEER,
                generation: verb.takes_generation().then_some(3),
            },
            counter: at as u64,
        };
        let mut out = [0u8; MAX_SEALED_LEN];
        let len = seal(&command, &Fixed::pinned(), &mut out).expect("seals");
        let sealed = open_sealed(
            &out[..len],
            &NODE,
            &mut ReplayWindow::<1>::new(),
            &Recording::answering(true),
        )
        .expect("opens");
        assert_eq!(sealed.verb, verb);
        assert_eq!(sealed.object, command.object);
        assert_eq!(sealed.counter, command.counter);
    }
    assert_eq!(Verb::of_word(b"open/passive"), None);
}

#[test]
fn the_longest_command_fills_the_stated_bounds_exactly() {
    let command = Command {
        verb: Verb::Reset,
        node: NODE,
        object: Object {
            peer: PEER,
            generation: Some(u64::MAX),
        },
        counter: u64::MAX,
    };
    let signer = Fixed::pinned();
    let mut out = [0u8; MAX_SEALED_LEN];
    assert_eq!(seal(&command, &signer, &mut out), Ok(MAX_SEALED_LEN));
    assert_eq!(signer.signed.borrow()[0].len(), MAX_TO_BE_SIGNED_LEN);
    let mut short = [0u8; MAX_SEALED_LEN - 1];
    assert_eq!(
        seal(&command, &signer, &mut short),
        Err(SealError::BufferTooSmall)
    );
}

#[test]
fn seal_refuses_a_command_it_could_not_open_and_a_signer_that_does_not_sign() {
    let mut out = [0u8; MAX_SEALED_LEN];
    let mut no_generation = pinned_command();
    no_generation.object.generation = None;
    assert_eq!(
        seal(&no_generation, &Fixed::pinned(), &mut out),
        Err(SealError::Malformed)
    );
    let mut close_with_generation = pinned_command();
    close_with_generation.verb = Verb::Close;
    assert_eq!(
        seal(&close_with_generation, &Fixed::pinned(), &mut out),
        Err(SealError::Malformed)
    );

    let mut compressed = Fixed::pinned();
    compressed.point[0] = 0x02;
    assert_eq!(
        seal(&pinned_command(), &compressed, &mut out),
        Err(SealError::Key)
    );

    let mut silent = Fixed::pinned();
    silent.signature = None;
    assert_eq!(
        seal(&pinned_command(), &silent, &mut out),
        Err(SealError::Signer)
    );
}

#[cfg(feature = "ring")]
mod with_ring {
    use super::*;

    fn sealed_by(signer: &RingSigner, command: &Command) -> Vec<u8> {
        let mut out = [0u8; MAX_SEALED_LEN];
        let len = seal(command, signer, &mut out).expect("seals");
        out[..len].to_vec()
    }

    fn reset(counter: u64) -> Command {
        Command {
            counter,
            ..pinned_command()
        }
    }

    /// Headers and a payload signed by `signer` whatever they say: what the reader refuses
    /// when the signature is genuine.
    fn signed_by(signer: &RingSigner, protected: &[u8], payload: &[u8]) -> Vec<u8> {
        let signature = signer
            .sign(&to_be_signed(protected, payload))
            .expect("signs");
        assemble(protected, payload, &signature)
    }

    fn protected_of(signer: &RingSigner) -> Vec<u8> {
        let mut out = [0u8; PROTECTED_LEN];
        let len = write_protected(&signer.point(), &mut out).expect("fits");
        out[..len].to_vec()
    }

    #[test]
    fn the_pinned_object_an_independent_signer_made_verifies() {
        let sealed = open_sealed(
            &hex(PINNED_SEALED_HEX),
            &NODE,
            &mut ReplayWindow::<1>::new(),
            &RingEs256,
        )
        .expect("openssl's signature verifies");
        assert_eq!(zid_text(&sealed.commander), PINNED_ZID_TEXT);
    }

    #[test]
    fn a_command_sealed_by_a_key_opens_to_that_keys_zid() {
        let signer = RingSigner::generate().expect("a key");
        let mut window = ReplayWindow::<2>::new();
        for (counter, verb) in Verb::ALL.into_iter().enumerate() {
            let command = Command {
                verb,
                node: NODE,
                object: Object {
                    peer: PEER,
                    generation: verb.takes_generation().then_some(9),
                },
                counter: counter as u64,
            };
            let sealed = open_sealed(
                &sealed_by(&signer, &command),
                &NODE,
                &mut window,
                &RingEs256,
            )
            .expect("opens");
            assert_eq!(sealed.commander, zid_of_point(&signer.point()));
            assert_eq!(
                (sealed.verb, sealed.object, sealed.counter),
                (command.verb, command.object, command.counter)
            );
        }
    }

    #[test]
    fn a_flipped_bit_anywhere_signed_is_a_bad_signature() {
        let signer = RingSigner::generate().expect("a key");
        let bytes = sealed_by(&signer, &reset(1));
        let signature_at = bytes.len() - SIGNATURE_LEN;
        let counter_at = signature_at - 2 - 1;
        let x_at = 2 + 2 + 16;
        assert_eq!(bytes[counter_at], 0x01, "the counter's byte");
        for at in [signature_at, bytes.len() - 1, counter_at, x_at] {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0x01;
            assert_eq!(
                open_sealed(&flipped, &NODE, &mut ReplayWindow::<1>::new(), &RingEs256),
                Err(SealError::BadSignature),
                "bit 0 of byte {at}"
            );
        }
    }

    #[test]
    fn another_key_put_in_place_of_the_signers_is_a_bad_signature() {
        let signer = RingSigner::generate().expect("a key");
        let other = RingSigner::generate().expect("a key");
        let bytes = sealed_by(&signer, &reset(1));
        let mut swapped = std::vec![0xd2, 0x84, 0x58, PROTECTED_LEN as u8];
        swapped.extend_from_slice(&protected_of(&other));
        swapped.extend_from_slice(&bytes[2 + 2 + PROTECTED_LEN..]);
        assert_eq!(
            open_sealed(&swapped, &NODE, &mut ReplayWindow::<1>::new(), &RingEs256),
            Err(SealError::BadSignature)
        );
    }

    #[test]
    fn an_older_counter_is_a_replay_and_a_forged_one_moves_nothing() {
        let signer = RingSigner::generate().expect("a key");
        let mut window = ReplayWindow::<1>::new();
        let mut forged = sealed_by(&signer, &reset(100));
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert_eq!(
            open_sealed(&forged, &NODE, &mut window, &RingEs256),
            Err(SealError::BadSignature)
        );
        assert!(open_sealed(
            &sealed_by(&signer, &reset(5)),
            &NODE,
            &mut window,
            &RingEs256
        )
        .is_ok());
        assert_eq!(
            open_sealed(
                &sealed_by(&signer, &reset(3)),
                &NODE,
                &mut window,
                &RingEs256
            ),
            Err(SealError::Replay { last: 5 })
        );
        assert_eq!(
            open_sealed(
                &sealed_by(&signer, &reset(5)),
                &NODE,
                &mut window,
                &RingEs256
            ),
            Err(SealError::Replay { last: 5 })
        );
        assert!(open_sealed(
            &sealed_by(&signer, &reset(6)),
            &NODE,
            &mut window,
            &RingEs256
        )
        .is_ok());
    }

    #[test]
    fn a_full_window_refuses_a_second_commander_and_still_serves_the_first() {
        let first = RingSigner::generate().expect("a key");
        let second = RingSigner::generate().expect("a key");
        let mut window = ReplayWindow::<1>::new();
        assert!(open_sealed(
            &sealed_by(&first, &reset(1)),
            &NODE,
            &mut window,
            &RingEs256
        )
        .is_ok());
        assert_eq!(
            open_sealed(
                &sealed_by(&second, &reset(1)),
                &NODE,
                &mut window,
                &RingEs256
            ),
            Err(SealError::WindowFull)
        );
        assert!(open_sealed(
            &sealed_by(&first, &reset(2)),
            &NODE,
            &mut window,
            &RingEs256
        )
        .is_ok());
    }

    #[test]
    fn a_genuine_signature_does_not_admit_another_encoding_or_algorithm() {
        let signer = RingSigner::generate().expect("a key");
        let protected = protected_of(&signer);
        let payload = hex(&payload_hex(RESET_HEX, "07", "19002a"));
        assert_eq!(
            open_sealed(
                &signed_by(&signer, &protected, &payload),
                &NODE,
                &mut ReplayWindow::<1>::new(),
                &RingEs256
            ),
            Err(SealError::NonCanonical)
        );
        let mut es384 = std::vec![0xa2, 0x01, 0x38, 0x22];
        es384.extend_from_slice(&protected[3..]);
        let payload = hex(&pinned_payload_hex());
        assert_eq!(
            open_sealed(
                &signed_by(&signer, &es384, &payload),
                &NODE,
                &mut ReplayWindow::<1>::new(),
                &RingEs256
            ),
            Err(SealError::Algorithm)
        );
        assert!(
            open_sealed(
                &signed_by(&signer, &protected, &payload),
                &NODE,
                &mut ReplayWindow::<1>::new(),
                &RingEs256
            )
            .is_ok(),
            "the control: the same signer over the format opens"
        );
    }

    #[test]
    fn a_genuine_command_for_another_node_is_refused() {
        let signer = RingSigner::generate().expect("a key");
        assert_eq!(
            open_sealed(
                &sealed_by(&signer, &reset(1)),
                &PEER,
                &mut ReplayWindow::<1>::new(),
                &RingEs256
            ),
            Err(SealError::WrongNode)
        );
    }

    #[test]
    fn a_pkcs8_document_that_holds_no_p256_key_is_refused() {
        assert!(matches!(
            RingSigner::from_pkcs8(&[0x30, 0x00]),
            Err(SealError::Key)
        ));
    }
}
