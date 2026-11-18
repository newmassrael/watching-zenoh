// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_get_to_peer`: a get addressed to one node by its zenoh id (policy `targeted-query`).
//!
//! A door wz has and zenoh-pico does not, so it is `wz_ext_*`, declared in `wz_ext.h` (the
//! extension namespace, apart from the drop-in headers). It takes what `z_get` takes and the id of
//! the node the get is for, and asks it on the one link that reaches that node: not on any other
//! link, not of the session's own queryables, not of a multicast group. A node the session has no
//! link to is not asked and the get is not widened to the others; it completes with no reply.
//! The id names a node, not a link or a queryable (`wz_session_core::peer_target`).
//!
//! The policy is the build's and off unless the build states it (`WZ_POLICY_TARGETED_QUERY`).
//! Off, the door refuses with `WZ_EXT_ERR_POLICY_OFF` and sends nothing, as the zenoh-c ABI's
//! `wz_capi_c_get_ext` refuses a target; an id of no bytes is `Z_ERR_INVALID`. On, a session
//! whose engine cannot address a get to one node (the cooperative engine) answers
//! `WZ_EXT_ERR_UNSUPPORTED` and asks no link. The callback and the moved parts of the options
//! are consumed on every path, a refusal included, as `z_get` consumes them; on a refusal the
//! callback's `drop(context)` runs before the door returns, which is the get reported over with
//! no reply.

use std::ffi::{c_char, CStr};

use wz_session_core::peer_target::{self, PeerTargetError};

use crate::abi::z_loaned_keyexpr_t;
use crate::get::{get_inner, z_get_options_t, z_moved_closure_reply_t};
use crate::result::{ZResult, WZ_EXT_ERR_POLICY_OFF, Z_ERR_INVALID, Z_ERR_NULL};
use crate::session::z_loaned_session_t;
use crate::zid::{z_id_t, Z_ID_SIZE};

/// The bytes a link names its node by: the id with its trailing zero bytes cut, as the wire
/// carries it and a face records it, so a padded `z_id_t` and a short wire id match. An id of no
/// non-zero byte has none.
fn wire_bytes(id: &[u8; Z_ID_SIZE]) -> Vec<u8> {
    let len = id.iter().rposition(|b| *b != 0).map_or(0, |last| last + 1);
    id[..len].to_vec()
}

/// The node `peer` names, admitted by a build whose `targeted-query` policy is `enabled`, or the
/// code the door answers: `Z_ERR_NULL` for no id, `WZ_EXT_ERR_POLICY_OFF` with the policy off,
/// `Z_ERR_INVALID` for an id that names no node.
fn addressed(peer: Option<&z_id_t>, enabled: bool) -> Result<Option<Vec<u8>>, ZResult> {
    let Some(peer) = peer else {
        return Err(Z_ERR_NULL);
    };
    let zid = wire_bytes(&peer.id);
    match peer_target::admit(Some(&zid), enabled) {
        Ok(()) => Ok(Some(zid)),
        Err(PeerTargetError::PolicyOff) => Err(WZ_EXT_ERR_POLICY_OFF),
        Err(PeerTargetError::Empty | PeerTargetError::TooLong(_)) => Err(Z_ERR_INVALID),
    }
}

/// `z_get`, addressed to the node `peer` names (see the module doc). `WZ_EXT_ERR_POLICY_OFF` in a
/// build whose `targeted-query` policy is off, `Z_ERR_INVALID` for an all-zero id, `Z_ERR_NULL`
/// for a null `peer`, and `WZ_EXT_ERR_UNSUPPORTED` from an engine that cannot address a get;
/// each sends nothing. Otherwise what `z_get` answers.
///
/// # Safety
/// As `z_get`; `peer` must be null or point to a readable `z_id_t`.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_get_to_peer(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    parameters: *const c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_get_options_t,
    peer: *const z_id_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        let len = if parameters.is_null() {
            0
        } else {
            CStr::from_ptr(parameters).to_bytes().len()
        };
        // A `const` item, so the build's value is folded and a build with the policy off keeps
        // only the refusal (as `get::issue_get` reads it).
        const ENABLED: bool = wz_session_core::policy::SessionPolicy::from_build().targeted_query;
        let target = addressed(peer.as_ref(), ENABLED);
        get_inner(zs, keyexpr, parameters, len, callback, options, target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(bytes: &[u8]) -> z_id_t {
        let mut id = [0u8; Z_ID_SIZE];
        id[..bytes.len()].copy_from_slice(bytes);
        z_id_t { id }
    }

    #[test]
    fn a_node_is_named_by_its_id_without_the_trailing_zero_bytes() {
        assert_eq!(
            wire_bytes(&id(&[0xc7, 0x00, 0x11]).id),
            vec![0xc7, 0x00, 0x11]
        );
        assert_eq!(wire_bytes(&id(&[0x5a; 16]).id), vec![0x5a; 16]);
        assert_eq!(wire_bytes(&id(&[]).id), Vec::<u8>::new());
    }

    #[test]
    fn a_target_is_admitted_only_with_the_policy_on_and_a_node_named() {
        let node = id(&[0xc7, 0xd1]);
        assert_eq!(addressed(Some(&node), true), Ok(Some(vec![0xc7, 0xd1])));
        assert_eq!(
            addressed(Some(&node), false),
            Err(WZ_EXT_ERR_POLICY_OFF),
            "with the policy off a node is refused by name, not asked"
        );
        assert_eq!(
            addressed(Some(&id(&[])), true),
            Err(Z_ERR_INVALID),
            "an all-zero id names no node"
        );
        assert_eq!(addressed(None, true), Err(Z_ERR_NULL));
        assert_eq!(addressed(None, false), Err(Z_ERR_NULL));
    }
}
