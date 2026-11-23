// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_result_t` — the pico return-code type.
//!
//! zenoh-pico declares `typedef int8_t z_result_t;`
//! (`include/zenoh-pico/utils/result.h:35`), with `Z_OK = 0`
//! (`_Z_RES_OK = 0`) and `_Z_ERR_GENERIC = -128` / `_Z_ERR_NULL = -127`.
//! Every exported function returning a status returns this `i8`, so a C
//! caller's `if (z_open(...) < 0)` check works unchanged.

/// The pico status type: `int8_t`.
pub type ZResult = i8;

/// Success. Matches pico `Z_OK` / `_Z_RES_OK`.
pub const Z_OK: ZResult = 0;

/// A channel `recv` found the channel closed and drained. Matches pico
/// `_Z_RES_CHANNEL_CLOSED` / `Z_CHANNEL_DISCONNECTED` = 1
/// (`utils/result.h:40-41`).
///
/// POSITIVE, unlike every error below: pico's channel loop is
/// `while (z_recv(..) == Z_OK)`, so a channel that ends must not read as a
/// failure to a caller testing `< 0`.
pub const Z_RES_CHANNEL_CLOSED: ZResult = 1;

/// A channel `try_recv` found the channel open but empty. Matches pico
/// `_Z_RES_CHANNEL_NODATA` / `Z_CHANNEL_NODATA` = 2 (`utils/result.h:42-43`).
pub const Z_RES_CHANNEL_NODATA: ZResult = 2;

/// Generic failure. Matches pico `_Z_ERR_GENERIC` (`utils/result.h:101`).
pub const Z_ERR_GENERIC: ZResult = -128;

/// A refcount increment passed pico's lazy `INT32_MAX` bound. Matches pico
/// `_Z_ERR_OVERFLOW` (`utils/result.h:96`).
pub const Z_ERR_OVERFLOW: ZResult = -74;

/// A required argument was NULL. Matches pico `_Z_ERR_NULL`
/// (`utils/result.h:100`).
pub const Z_ERR_NULL: ZResult = -127;

/// An argument was non-NULL but otherwise invalid (bad UTF-8, malformed
/// endpoint string, etc.). Round 1 collapses the pico fine-grained error
/// taxonomy onto this single "invalid argument" code; exact per-call code
/// parity is a follow-up refinement.
pub const Z_ERR_INVALID: ZResult = -1;

/// A reply keyexpr is not covered by the query it answers. Matches pico
/// `_Z_ERR_KEYEXPR_NOT_MATCH` (`utils/result.h:63`) EXACTLY, rather than
/// collapsing onto [`Z_ERR_INVALID`]: this is the one code a queryable is
/// expected to branch on (`z_query_reply` is the only place pico raises it,
/// `src/net/primitives.c:439`), so a C program that checks for it must see it.
pub const Z_ERR_KEYEXPR_NOT_MATCH: ZResult = -108;

/// `z_undeclare_keyexpr` was handed a keyexpr another session declared.
/// Matches pico `_Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION`
/// (`include/zenoh-pico/utils/result.h`) EXACTLY, for the reason the two codes
/// around it are not collapsed: it is the one answer that tells a caller its
/// retraction went to the wrong session rather than failed.
pub const Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION: ZResult = -70;

/// A get was issued with a cancellation token that had ALREADY cancelled.
/// Matches pico `Z_ERR_CANCELLED` (`utils/result.h:98`) EXACTLY, for the reason
/// [`Z_ERR_KEYEXPR_NOT_MATCH`] is not collapsed either: it is a code the caller
/// is expected to branch on. Upstream raises it from
/// `_z_cancellation_token_add_on_cancel_handler`
/// (`src/session/cancellation.c:171-181`) and returns it out of `_z_query`
/// without sending a Query, so a C program that hands over a spent token must
/// see this rather than a generic failure or a success.
pub const Z_ERR_CANCELLED: ZResult = -69;

/// `z_timestamp_new` has no time left to give: the session already gave the greatest one there
/// is, and every time it gives is greater than the last. Matches pico
/// (`vendor/zenoh-pico/include/zenoh-pico/utils/result.h` @
/// `_Z_ERR_TIMESTAMP_GENERATION_FAILED = -68,`) EXACTLY, the code pico's own `z_timestamp_new`
/// returns for it.
pub const Z_ERR_TIMESTAMP_GENERATION_FAILED: ZResult = -68;

/// The session this call names is closed, or is not a session at all. Matches
/// pico `_Z_ERR_SESSION_CLOSED` (`utils/result.h`) EXACTLY: a caller declaring a
/// listener branches on it to learn the declaration was refused for want of a
/// live session, which [`Z_ERR_INVALID`]'s collapsed `-1` cannot say.
pub const Z_ERR_SESSION_CLOSED: ZResult = -73;

/// An argument was handed over in a state the call cannot use — a moved
/// transport that holds no transport, for one. Matches pico `_Z_ERR_INVALID` /
/// `Z_EINVAL` (`utils/result.h`) EXACTLY, where [`Z_ERR_INVALID`] is the
/// collapsed `-1` every older export here answers with. The connectivity plane
/// uses this one because its refusals are the ones a program branches on.
pub const Z_EINVAL: ZResult = -75;

/// A `z_open` whose config names no locator scouted and nobody answered. Matches
/// pico `_Z_ERR_SCOUT_NO_RESULTS` (`utils/result.h`), which `_z_open` returns for
/// a scout that found nothing and for a build that cannot scout at all
/// (`vendor/zenoh-pico/src/net/session.c` @ `ret = _Z_ERR_SCOUT_NO_RESULTS;`).
pub const Z_ERR_SCOUT_NO_RESULTS: ZResult = -87;

/// A `z_open` whose `listen` locator names a kind of link this build has none of. Matches
/// pico `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN` (`utils/result.h`), which its listen link
/// answers when no link it carries takes the endpoint (`vendor/zenoh-pico/src/link/link.c` @
/// `ret = _Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;`): a multicast group in a build without the
/// multicast transport, a scheme no link serves (MEASURED on the real library: `nope/...` and,
/// in a build without its raweth transport, `reth/...`).
pub const Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN: ZResult = -92;

/// A `z_open` whose config's mode is neither `client` nor `peer` (`router` among them: pico has
/// no router role). Matches pico `_Z_ERR_CONFIG_INVALID_MODE` (`utils/result.h`), which its
/// open answers for such a mode (`vendor/zenoh-pico/src/net/session.c` @
/// `ret = _Z_ERR_CONFIG_INVALID_MODE;`).
pub const Z_ERR_CONFIG_INVALID_MODE: ZResult = -90;

/// The session has no transport to do this on: a client whose link is gone and has not come
/// back. Matches pico `_Z_ERR_TRANSPORT_NOT_AVAILABLE` (`utils/result.h`), which its three
/// `zp_batch_*` answer when `_z_transport_get_common` finds the transport cleared
/// (`vendor/zenoh-pico/src/transport/transport.c` @ `_Z_ERROR_RETURN(_Z_ERR_TRANSPORT_NOT_AVAILABLE);`;
/// MEASURED on the real library by `tests/z_api_batching_test.c`).
pub const Z_ERR_TRANSPORT_NOT_AVAILABLE: ZResult = -103;

/// Open-debt item 911 (found on the way) — a `z_open` whose listen or connect link could not be
/// opened. Matches pico `_Z_ERR_TRANSPORT_OPEN_FAILED` (`utils/result.h`), which its link
/// answers when the link it took does not open (`vendor/zenoh-pico/src/link/link.c` @
/// `ret = _Z_ERR_TRANSPORT_OPEN_FAILED;`; MEASURED on the real library: a listen on a port held
/// elsewhere, a client connect to a port nobody listens on).
pub const Z_ERR_TRANSPORT_OPEN_FAILED: ZResult = -102;

/// A put or delete the session did not send: its congestion control let it be dropped, and
/// another sender held the transmit lock (here, the conduit or the session) it needed. Matches
/// pico `_Z_ERR_TRANSPORT_TX_FAILED`
/// (`vendor/zenoh-pico/include/zenoh-pico/utils/result.h` @ `_Z_ERR_TRANSPORT_TX_FAILED = -100,`),
/// which its put answers for a send that failed
/// (`vendor/zenoh-pico/src/net/primitives.c` @
/// `if (_z_send_n_msg(zn, &msg, reliability, cong_ctrl, NULL) != _Z_RES_OK) {`), as its dropping
/// send does on a held lock (`vendor/zenoh-pico/src/transport/common/tx.c` @
/// `_Z_INFO("Dropping zenoh message because of congestion control");`).
pub const Z_ERR_TRANSPORT_TX_FAILED: ZResult = -100;

/// An allocation failed. Matches pico `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
/// (`utils/result.h`).
pub const Z_ERR_SYSTEM_OUT_OF_MEMORY: ZResult = -78;

/// A value the caller configured an object with is refused. Matches pico
/// `_Z_ERR_CONFIG_INVALID_VALUE` (`utils/result.h`). Kept apart from
/// [`Z_EINVAL`] where one door refuses both: the segment sender's
/// `wz_ext_segment_sender_new` answers this for a profile or values text it
/// refuses, and `Z_EINVAL` for an argument it cannot read at all.
pub const Z_ERR_CONFIG_INVALID_VALUE: ZResult = -89;

/// A config's insert could not keep the value. Matches pico
/// `_Z_ERR_CONFIG_FAILED_INSERT` (`vendor/zenoh-pico/include/zenoh-pico/utils/result.h` @
/// `_Z_ERR_CONFIG_FAILED_INSERT = -95,`), which its insert answers when the value is not kept: here
/// a new key past the config's rows or a value past its text.
pub const Z_ERR_CONFIG_FAILED_INSERT: ZResult = -95;

/// A wz door (`wz_ext.h`) was asked for something this build's policy does not
/// allow: a get addressed to one node (`wz_ext_get_to_peer`) while the
/// `targeted-query` policy is off. Nothing was sent. Not `Z_EINVAL`, which says
/// the value is wrong: the same call is right in a build whose policy is on.
/// wz's own code, outside pico's (which run from -128 to -65, beside the
/// collapsed [`Z_ERR_INVALID`]), so a later pico code cannot take it.
pub const WZ_EXT_ERR_POLICY_OFF: ZResult = -2;

/// The engine the session runs on does not do what a wz door asked: the
/// cooperative engine watches no peer's declarations and addresses no get to one
/// node, and a build without a plane hears no declaration of it. Nothing was
/// declared or sent. wz's own code, for the reason [`WZ_EXT_ERR_POLICY_OFF`] is.
pub const WZ_EXT_ERR_UNSUPPORTED: ZResult = -3;

/// A call of the program's into its transport (`wz_ext_transport_*`) named a link the transport
/// does not hold: it never did, or the session has let it go. wz's own code, for the reason
/// [`WZ_EXT_ERR_POLICY_OFF`] is, as are the three after it.
pub const WZ_EXT_ERR_LINK_UNKNOWN: ZResult = -4;

/// A call of the program's into its transport named a link that is not up yet: bytes or an accept
/// before the program said the link is connected.
pub const WZ_EXT_ERR_LINK_NOT_OPEN: ZResult = -5;

/// A call of the program's into its transport named a link that is closing or closed: the bytes
/// were not taken.
pub const WZ_EXT_ERR_LINK_CLOSED: ZResult = -6;

/// A call of the program's into its transport does not apply to the link's kind: bytes handed to a
/// listener, an accept on a link that is not one.
pub const WZ_EXT_ERR_LINK_KIND: ZResult = -7;

/// A call of the program's into its transport handed bytes to a link that already queues its
/// bound (`APP_LINK_QUEUE_BYTES`) of bytes the session has not read: nothing was taken. The
/// program hands the same bytes in again after its `drained` call for the link.
pub const WZ_EXT_ERR_LINK_FULL: ZResult = -8;

/// A message payload's door (`wz_ext_message_payload_*`) was given a field path that names no field
/// it addresses: not a path, a name the message has not, an index on a field that is not repeated,
/// a repeated field where an element is named or the other way round, a map or a group. Nothing
/// changed. wz's own code, for the reason [`WZ_EXT_ERR_POLICY_OFF`] is, as are the four after it.
pub const WZ_EXT_ERR_PAYLOAD_PATH: ZResult = -20;

/// The value given to a field is not of its type, or the field's value was asked for as another.
pub const WZ_EXT_ERR_PAYLOAD_TYPE: ZResult = -21;

/// The value does not fit its field (or what it was asked for as), or an index is past the end of
/// its list.
pub const WZ_EXT_ERR_PAYLOAD_RANGE: ZResult = -22;

/// The field is not set: one with presence, a field of a message that is not there, or a required
/// field of an encoding.
pub const WZ_EXT_ERR_PAYLOAD_ABSENT: ZResult = -23;

/// The bytes handed to the decoding door are not a message of the schema; the payload is as it
/// was.
pub const WZ_EXT_ERR_PAYLOAD_WIRE: ZResult = -24;

/// A scout (`z_scout`, or the lookup of a `z_open` whose config names no locator) was asked on a
/// thread whose own scouting window is still delivering: from inside a scout's callback. The
/// cooperative engine has one table of Hellos, which that window holds until its callbacks return,
/// so the scout is refused at once rather than wait on itself. wz's own code, for the reason
/// [`WZ_EXT_ERR_POLICY_OFF`] is.
pub const WZ_EXT_ERR_SCOUT_REENTERED: ZResult = -25;

#[cfg(test)]
mod tests {
    use super::*;

    /// The wz codes are errors to a caller's `< 0` test, differ from each other and from every
    /// code this file transcribes from pico.
    #[test]
    fn the_wz_codes_are_errors_of_their_own() {
        let pico = [
            Z_ERR_GENERIC,
            Z_ERR_OVERFLOW,
            Z_ERR_NULL,
            Z_ERR_INVALID,
            Z_ERR_KEYEXPR_NOT_MATCH,
            Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION,
            Z_ERR_CANCELLED,
            Z_ERR_TIMESTAMP_GENERATION_FAILED,
            Z_ERR_SESSION_CLOSED,
            Z_EINVAL,
            Z_ERR_SCOUT_NO_RESULTS,
            Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
            Z_ERR_CONFIG_INVALID_MODE,
            Z_ERR_TRANSPORT_NOT_AVAILABLE,
            Z_ERR_TRANSPORT_OPEN_FAILED,
            Z_ERR_TRANSPORT_TX_FAILED,
            Z_ERR_SYSTEM_OUT_OF_MEMORY,
            Z_ERR_CONFIG_INVALID_VALUE,
            Z_ERR_CONFIG_FAILED_INSERT,
        ];
        let wz = [
            WZ_EXT_ERR_POLICY_OFF,
            WZ_EXT_ERR_UNSUPPORTED,
            WZ_EXT_ERR_LINK_UNKNOWN,
            WZ_EXT_ERR_LINK_NOT_OPEN,
            WZ_EXT_ERR_LINK_CLOSED,
            WZ_EXT_ERR_LINK_KIND,
            WZ_EXT_ERR_LINK_FULL,
            WZ_EXT_ERR_PAYLOAD_PATH,
            WZ_EXT_ERR_PAYLOAD_TYPE,
            WZ_EXT_ERR_PAYLOAD_RANGE,
            WZ_EXT_ERR_PAYLOAD_ABSENT,
            WZ_EXT_ERR_PAYLOAD_WIRE,
            WZ_EXT_ERR_SCOUT_REENTERED,
        ];
        for (at, code) in wz.iter().enumerate() {
            assert!(*code < 0, "{code} must read as a failure");
            assert!(!pico.contains(code), "{code} is a pico code");
            assert!(!wz[..at].contains(code), "{code} is given twice");
        }
    }
}
