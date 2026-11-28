// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The verifier of the sealed lifecycle commands a node of the heap profile is sent (decision D17
//! of `docs/session-lifecycle-intent.md`, the format `docs/command-seal.md`): the node's zid,
//! ES256 by `ring`, which the TLS links of this runtime already link, and the freshness of each
//! commander, started with an echo drawn from the OS when the node starts.
//!
//! The replay window evicts no commander (forgetting one would let every command it sealed be
//! replayed once more), so it must hold every commander the node's declaration grants a verb to.
//! The heap profile reads its grants when it starts, and the window is a table of fixed size, so a
//! declaration that grants more commanders than the table holds is refused here, by name, before
//! any command is taken, rather than found out when a granted commander is refused for room.

use std::fmt;

use wz_command_seal::RingEs256;
use wz_session_core::credential_identity::zid_from_key_text;
use wz_session_core::lifecycle_monitor::HeapGrants;
use wz_session_core::sealed_command::seal::{Echo, Freshness, ECHO_LEN};
use wz_session_core::sealed_command::SealedCommands;

/// The commanders whose last counter a heap node keeps. A declaration names the operators and
/// controllers that may command one node, a handful in a deployment, and every one of them must
/// fit, since the window evicts none; 64 leaves room far past that for the cost of 64 rows of a
/// zid and a counter, 2 KiB in the node's queries, which a sealed command scans once.
pub const HEAP_SEALED_COMMANDERS: usize = 64;

/// The verifier `LifecycleQueries::with_seal` takes on the heap profile.
pub type HeapSeal = SealedCommands<RingEs256, HEAP_SEALED_COMMANDERS>;

/// Why a heap node verifies no sealed command.
#[derive(Debug)]
pub enum LifecycleSealError {
    /// The node's zid is not spelled as a lifecycle key spells one, so no command names it.
    NotAZid,
    /// The declaration grants verbs to more commanders than the window keeps counters for.
    TooManyCommanders {
        /// The commanders the declaration grants a verb to.
        granted: usize,
    },
    /// The OS gave no entropy for the echo of this start.
    Entropy(getrandom::Error),
}

impl fmt::Display for LifecycleSealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAZid => {
                f.write_str("the node's zid is not lowercase hex with no leading zero")
            }
            Self::TooManyCommanders { granted } => write!(
                f,
                "the declaration grants verbs to {granted} commanders and a node keeps the \
                 counters of {HEAP_SEALED_COMMANDERS}"
            ),
            Self::Entropy(why) => {
                write!(f, "no entropy for the echo of the sealed commands ({why})")
            }
        }
    }
}

/// The verifier of the node `zid_hex` (zenoh's spelling, as the node's lifecycle keys carry it)
/// for the commanders `grants` names, after a start that remembers no counter: each commander's
/// first command carries an echo drawn here from the OS (RFC 8613, appendix B.1.2).
pub fn lifecycle_seal_from_os_entropy(
    zid_hex: &str,
    grants: &HeapGrants,
) -> Result<HeapSeal, LifecycleSealError> {
    let mut echo: Echo = [0u8; ECHO_LEN];
    getrandom::getrandom(&mut echo).map_err(LifecycleSealError::Entropy)?;
    lifecycle_seal_with_echo(zid_hex, grants, echo)
}

/// [`lifecycle_seal_from_os_entropy`] with the echo given.
fn lifecycle_seal_with_echo(
    zid_hex: &str,
    grants: &HeapGrants,
    echo: Echo,
) -> Result<HeapSeal, LifecycleSealError> {
    let node = zid_from_key_text(zid_hex).ok_or(LifecycleSealError::NotAZid)?;
    let granted = granted_commanders(grants);
    if granted > HEAP_SEALED_COMMANDERS {
        return Err(LifecycleSealError::TooManyCommanders { granted });
    }
    Ok(SealedCommands::new(node, RingEs256, Freshness::echo(echo)))
}

/// The commanders `grants` names, each once: a zid granted on several rows takes one counter.
fn granted_commanders(grants: &HeapGrants) -> usize {
    let rows = grants.grants();
    rows.iter()
        .enumerate()
        .filter(|&(at, grant)| {
            !rows
                .iter()
                .take(at)
                .any(|earlier| earlier.commander == grant.commander)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_command_seal::{
        seal, zid_of_point, Command, Es256Signer, Object, RingSigner, Verb, Zid, MAX_SEALED_LEN,
    };
    use wz_session_core::sealed_command::{SealRefused, SealVerifier};

    /// The node the tests verify for, and the peer their commands name.
    const NODE: &str = "a1b2c3";
    const PEER: &str = "d4";

    fn zid(text: &str) -> Zid {
        zid_from_key_text(text).expect("a zid")
    }

    fn zid_text(zid: &Zid) -> String {
        format!("{:x}", u128::from_le_bytes(*zid))
    }

    /// The grants of `commanders`, `close` and `status` each.
    fn grants(commanders: &[Zid]) -> HeapGrants {
        let rows: Vec<String> = commanders
            .iter()
            .map(|commander| format!("{}=close,status", zid_text(commander)))
            .collect();
        HeapGrants::parse(rows.iter().map(String::as_str)).expect("grants")
    }

    /// `signer`'s `status` of [`PEER`] at `node`, sealed.
    fn status(signer: &RingSigner, node: Zid, counter: u64, echo: Option<Echo>) -> Vec<u8> {
        let command = Command {
            verb: Verb::Status,
            node,
            object: Object {
                peer: zid(PEER),
                generation: None,
            },
            counter,
            echo,
        };
        let mut out = [0u8; MAX_SEALED_LEN];
        let len = seal(&command, signer, &mut out).expect("seals");
        out.get(..len).expect("the sealed length").to_vec()
    }

    /// A granted commander's command, sealed with `ring`, verifies for this node's zid and is
    /// challenged for the echo of this start; carrying it, the command is taken once. Red if the
    /// verifier were built for another zid, verified with another ES256 or started remembering a
    /// counter.
    #[test]
    fn a_granted_commanders_command_verifies_and_carries_the_echo_of_this_start() {
        let signer = RingSigner::generate().expect("a key");
        let commander = zid_of_point(&signer.point());
        let echo = [0x3c; ECHO_LEN];
        let verifier =
            lifecycle_seal_with_echo(NODE, &grants(&[commander]), echo).expect("a verifier");

        let first = verifier
            .verify(&status(&signer, zid(NODE), 1, None))
            .expect("a command for this node verifies");
        assert_eq!(first.sealed().commander, commander);
        assert_eq!(
            verifier.check(first.sealed()),
            Err(SealRefused::EchoRequired { echo })
        );

        let repeat = verifier
            .verify(&status(&signer, zid(NODE), 2, Some(echo)))
            .expect("the repeat verifies");
        assert_eq!(verifier.check(repeat.sealed()), Ok(()));
        assert!(verifier.take(repeat).is_ok(), "the repeat is taken");
        let again = verifier
            .verify(&status(&signer, zid(NODE), 2, Some(echo)))
            .expect("the same command verifies");
        assert_eq!(
            verifier.check(again.sealed()),
            Err(SealRefused::Replay { last: 2 })
        );
    }

    /// A command for another node is refused by the verifier, whoever sealed it. Red if the
    /// verifier were built for a zid other than the one the node's keys spell.
    #[test]
    fn a_command_for_another_node_is_refused() {
        let signer = RingSigner::generate().expect("a key");
        let commander = zid_of_point(&signer.point());
        let verifier = lifecycle_seal_with_echo(NODE, &grants(&[commander]), [0; ECHO_LEN])
            .expect("a verifier");
        assert_eq!(
            verifier
                .verify(&status(&signer, zid("a1b2c4"), 1, None))
                .err(),
            Some(SealRefused::WrongNode)
        );
    }

    /// A declaration may grant as many commanders as the window holds and no more; a zid granted
    /// on two rows is one commander. Red if the bound moved or a commander were counted per row.
    #[test]
    fn the_declaration_grants_no_more_commanders_than_the_window_holds() {
        let commanders: Vec<Zid> = (1..=HEAP_SEALED_COMMANDERS + 1)
            .map(|n| u128::try_from(n).expect("a small number").to_le_bytes())
            .collect();
        let fits = commanders
            .get(..HEAP_SEALED_COMMANDERS)
            .expect("as many commanders as the window holds");
        assert!(lifecycle_seal_with_echo(NODE, &grants(fits), [0; ECHO_LEN]).is_ok());
        assert!(matches!(
            lifecycle_seal_with_echo(NODE, &grants(&commanders), [0; ECHO_LEN]),
            Err(LifecycleSealError::TooManyCommanders { granted }) if granted == HEAP_SEALED_COMMANDERS + 1
        ));
        let mut rows: Vec<String> = fits
            .iter()
            .map(|commander| format!("{}=close", zid_text(commander)))
            .collect();
        let again = fits.first().expect("a commander");
        rows.push(format!("{}=status", zid_text(again)));
        let twice = HeapGrants::parse(rows.iter().map(String::as_str)).expect("grants");
        assert_eq!(granted_commanders(&twice), HEAP_SEALED_COMMANDERS);
        assert!(lifecycle_seal_with_echo(NODE, &twice, [0; ECHO_LEN]).is_ok());
    }

    /// A node whose zid no lifecycle key can spell verifies nothing, and no grant is read for it.
    /// Red if a zid with a leading zero or an uppercase digit were taken.
    #[test]
    fn a_zid_no_key_spells_is_refused() {
        for text in ["0a1b", "A1B2", ""] {
            assert!(matches!(
                lifecycle_seal_with_echo(text, &HeapGrants::default(), [0; ECHO_LEN]),
                Err(LifecycleSealError::NotAZid)
            ));
        }
    }

    /// Two starts draw two echoes from the OS, so a command sealed for one start carries no echo
    /// the next one takes. Red if the echo were a constant.
    #[test]
    fn each_start_draws_its_own_echo() {
        let signer = RingSigner::generate().expect("a key");
        let commander = zid_of_point(&signer.point());
        let granted = grants(&[commander]);
        let challenge = |verifier: &HeapSeal| {
            let verified = verifier
                .verify(&status(&signer, zid(NODE), 1, None))
                .expect("verifies");
            match verifier.check(verified.sealed()) {
                Err(SealRefused::EchoRequired { echo }) => echo,
                other => panic!("a started node challenges a new commander: {other:?}"),
            }
        };
        let one = lifecycle_seal_from_os_entropy(NODE, &granted).expect("a verifier");
        let two = lifecycle_seal_from_os_entropy(NODE, &granted).expect("a verifier");
        assert_ne!(challenge(&one), challenge(&two));
    }
}
