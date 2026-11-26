// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The code of a call the engine refused, by the door it was refused at.
//!
//! Apart from [`crate::result`] because the additional library (`wz-capi-pico-ext`) compiles that
//! file again, and that library names no crate of the engine port: this table reads the port's
//! [`Refusal`] and the doors of this build's features.

use wz_capi_port::Refusal;

use crate::result::{
    ZResult, ZEXT_ERR_UNSUPPORTED, Z_ERR_GENERIC, Z_ERR_OVERFLOW, Z_ERR_SESSION_CLOSED,
    Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_ERR_TRANSPORT_TX_FAILED,
};

/// The door of the C library a declaration was refused at. zenoh-pico answers one cause
/// differently at different doors, so the code [`refusal_code`] answers is the pair's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Door {
    /// A publisher's or a querier's matching listener, with a handle or in the background
    /// (`z_publisher_declare_matching_listener`, `z_querier_declare_matching_listener` and their
    /// `_background_` forms).
    MatchingListener,
    /// The write filter a publisher or a querier is declared with (`z_declare_publisher`,
    /// `z_declare_querier`, the advanced publisher's), made after the entity's key is declared.
    WriteFilter,
    /// The declaration of a key expression, made for an entity's key or by `z_declare_keyexpr`.
    Keyexpr,
    /// A subscriber, a liveliness subscriber or a queryable, declared once its key is.
    Entity,
    /// What a session is asked of itself apart from any entity: the watch of its faces its open
    /// makes for the connectivity plane, and `zp_send_join`.
    #[cfg(any(
        feature = "connectivity",
        all(feature = "multicast-transport", not(feature = "multi-thread"))
    ))]
    Session,
    /// A watch of what the peers declare (`zext_decl_watch_declare`), wz's own door, which a
    /// build without the declaration watch has none of.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    DeclWatch,
    /// A liveliness token, declared once its key is, which a build without liveliness has none of.
    #[cfg(feature = "liveliness")]
    Token,
    /// A get, a querier's get or a liveliness get (`z_get`, `z_querier_get`, `z_liveliness_get`),
    /// which a build without the querying end has none of.
    #[cfg(feature = "query")]
    Get,
}

/// The code of a call the engine refused at `door`: this ABI's one table for the port's
/// [`Refusal`], each door's row the code zenoh-pico's own door answers for the cause. A plane the
/// build does not hold, and a statement the engine does not carry out, have no pico code at any
/// door, as zenoh-pico has neither; each is wz's [`ZEXT_ERR_UNSUPPORTED`].
pub(crate) fn refusal_code(refusal: Refusal, door: Door) -> ZResult {
    if matches!(refusal, Refusal::NotBuilt | Refusal::NotHonoured(_)) {
        return ZEXT_ERR_UNSUPPORTED;
    }
    // An entity copies its key, which takes one more holder of the key's declaration, and pico
    // refuses that copy at every door with its code for a count past its bound
    // (`vendor/zenoh-pico/src/collections/refcount.c` @ `_Z_ERROR_RETURN(_Z_ERR_OVERFLOW);`).
    if refusal == Refusal::KeyHoldsFull {
        return Z_ERR_OVERFLOW;
    }
    match door {
        // A listener pico has no room for is `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`), and one
        // asked of a session that is not open is the generic error: the door reads it as a weak
        // reference that did not upgrade (`vendor/zenoh-pico/src/api/api.c` @
        // `z_result_t z_publisher_declare_matching_listener(const z_loaned_publisher_t *publisher,`,
        // and the querier's twin).
        Door::MatchingListener => match refusal {
            Refusal::Closed => Z_ERR_GENERIC,
            _ => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
        // A filter pico has no room for is `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, and one on a session that
        // is closed is the generic error: its Interest is not registered on a closed session, and
        // the filter reads the Interest id 0 it is handed back as a failure
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `if (filter->_interest_id == 0) {`). A key the
        // session must declare first is refused before the filter, by the key's own door.
        Door::WriteFilter => match refusal {
            Refusal::Closed => Z_ERR_GENERIC,
            _ => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
        // pico registers a key's declaration, and a token, under the session's lock taken only
        // while it is open (`vendor/zenoh-pico/src/session/resource.c` @
        // `_Z_RETURN_IF_ERR(_z_session_mutex_lock_if_open(zn));`), so a closed session refuses them
        // with `_Z_ERR_SESSION_CLOSED`; a subscriber's or a queryable's
        // registration on a closed session comes back empty, which its declaration answers with
        // `_Z_ERR_SYSTEM_OUT_OF_MEMORY` as it answers one it has no room for
        // (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_subscription_rc_t sp_s = _z_register_subscription(_Z_RC_IN_VAL(zn), _Z_SUBSCRIBER_KIND_SUBSCRIBER, &s);`).
        // A declaration no link could carry is the failed send pico answers it with.
        Door::Keyexpr => match refusal {
            Refusal::Closed => Z_ERR_SESSION_CLOSED,
            Refusal::ExceedsCapacity => Z_ERR_TRANSPORT_TX_FAILED,
            _ => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
        #[cfg(feature = "liveliness")]
        Door::Token => refusal_code(refusal, Door::Keyexpr),
        // zenoh-pico has no such door: a closed session answers pico's code for one, and a table at
        // its bound the code pico answers an entity it has no room for.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        Door::DeclWatch => match refusal {
            Refusal::Closed => Z_ERR_SESSION_CLOSED,
            _ => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
        // pico answers a call on a session that is not open with `_Z_ERR_SESSION_CLOSED`
        // (`vendor/zenoh-pico/src/net/primitives.c` @
        // `return _z_session_is_closed(zn) ? _Z_ERR_SESSION_CLOSED : _Z_RES_OK;`), and has no other
        // refusal of these.
        #[cfg(any(
            feature = "connectivity",
            all(feature = "multicast-transport", not(feature = "multi-thread"))
        ))]
        Door::Session => match refusal {
            Refusal::Closed => Z_ERR_SESSION_CLOSED,
            _ => Z_ERR_GENERIC,
        },
        Door::Entity => match refusal {
            Refusal::ExceedsCapacity => Z_ERR_TRANSPORT_TX_FAILED,
            _ => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
        // A get pico has no room to hold pending is `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `_z_liveliness_pending_query_t *pq = _z_unsafe_liveliness_register_pending_query(zn);`),
        // one asked of a session that is closed is `_Z_ERR_SESSION_CLOSED`
        // (`vendor/zenoh-pico/src/net/primitives.c` @
        // `return _z_session_is_closed(zn) ? _Z_ERR_SESSION_CLOSED : _Z_RES_OK;`), and one larger
        // than the session's codec carries the generic error, as a publication of one is.
        #[cfg(feature = "query")]
        Door::Get => match refusal {
            Refusal::Closed => Z_ERR_SESSION_CLOSED,
            Refusal::ExceedsCapacity => Z_ERR_GENERIC,
            _ => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each refusal at a write filter's door answers the code pico's door answers, and every code
    /// is a failure to a caller's `< 0` test: none reads as the `Z_OK` of a declaration that
    /// was never made.
    #[test]
    fn each_refusal_of_a_write_filter_answers_picos_code() {
        let at = |refusal| refusal_code(refusal, Door::WriteFilter);
        assert_eq!(at(Refusal::TableFull), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::KeyTooLong), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::NoEntityId), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::Closed), Z_ERR_GENERIC);
        assert_eq!(at(Refusal::NotBuilt), ZEXT_ERR_UNSUPPORTED);
    }

    /// A get pico has no room for is out of memory, one on a closed session is
    /// `Z_ERR_SESSION_CLOSED`, and a statement the engine does not carry out is wz's own code.
    #[cfg(feature = "query")]
    #[test]
    fn each_refusal_of_a_get_answers_picos_code() {
        let at = |refusal| refusal_code(refusal, Door::Get);
        assert_eq!(at(Refusal::TableFull), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::Closed), Z_ERR_SESSION_CLOSED);
        assert_eq!(at(Refusal::ExceedsCapacity), Z_ERR_GENERIC);
        assert_eq!(at(Refusal::NotBuilt), ZEXT_ERR_UNSUPPORTED);
        assert_eq!(
            at(Refusal::NotHonoured(
                wz_capi_port::StatementNotHonoured::TargetPeer
            )),
            ZEXT_ERR_UNSUPPORTED
        );
    }

    /// A declaration whose count of holders is full refuses the entity that would hold it with
    /// pico's code for a count past its bound, at every door an entity is declared at. Turned red by
    /// a `refusal_code` that reads it as a full table (out of memory).
    #[test]
    fn a_full_count_of_holders_answers_picos_overflow_at_every_door() {
        for door in [Door::Keyexpr, Door::Entity, Door::WriteFilter] {
            assert_eq!(refusal_code(Refusal::KeyHoldsFull, door), Z_ERR_OVERFLOW);
        }
        #[cfg(feature = "liveliness")]
        assert_eq!(
            refusal_code(Refusal::KeyHoldsFull, Door::Token),
            Z_ERR_OVERFLOW
        );
        assert_eq!(
            refusal_code(Refusal::TableFull, Door::Entity),
            Z_ERR_SYSTEM_OUT_OF_MEMORY,
            "CONTROL: a full table keeps its own code"
        );
    }

    /// A key's declaration and a token on a closed session are `Z_ERR_SESSION_CLOSED`, where an
    /// entity's registration there is out of memory, as pico answers each; a full table is out of
    /// memory at every one of them.
    #[test]
    fn each_refusal_of_a_declaration_answers_picos_code() {
        for door in [Door::Keyexpr, Door::Entity] {
            assert_eq!(
                refusal_code(Refusal::TableFull, door),
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert_eq!(
                refusal_code(Refusal::NoEntityId, door),
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert_eq!(
                refusal_code(Refusal::ExceedsCapacity, door),
                Z_ERR_TRANSPORT_TX_FAILED
            );
            assert_eq!(refusal_code(Refusal::NotBuilt, door), ZEXT_ERR_UNSUPPORTED);
        }
        assert_eq!(
            refusal_code(Refusal::Closed, Door::Keyexpr),
            Z_ERR_SESSION_CLOSED
        );
        #[cfg(feature = "liveliness")]
        assert_eq!(
            refusal_code(Refusal::Closed, Door::Token),
            Z_ERR_SESSION_CLOSED
        );
        assert_eq!(
            refusal_code(Refusal::Closed, Door::Entity),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
    }

    /// A session closed under a call on itself answers pico's code for a closed session.
    #[cfg(any(
        feature = "connectivity",
        all(feature = "multicast-transport", not(feature = "multi-thread"))
    ))]
    #[test]
    fn a_refusal_of_the_session_itself_answers_picos_code() {
        assert_eq!(
            refusal_code(Refusal::Closed, Door::Session),
            Z_ERR_SESSION_CLOSED
        );
        assert_eq!(
            refusal_code(Refusal::TableFull, Door::Session),
            Z_ERR_GENERIC
        );
        assert_eq!(
            refusal_code(Refusal::NotBuilt, Door::Session),
            ZEXT_ERR_UNSUPPORTED
        );
    }

    /// A watch the engine or the build does not carry is wz's unsupported code, one on a closed
    /// session pico's closed code, and one past the observers' table out of memory.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    #[test]
    fn each_refusal_of_a_declaration_watch_answers_its_code() {
        let at = |refusal| refusal_code(refusal, Door::DeclWatch);
        assert_eq!(at(Refusal::NotBuilt), ZEXT_ERR_UNSUPPORTED);
        assert_eq!(at(Refusal::Closed), Z_ERR_SESSION_CLOSED);
        assert_eq!(at(Refusal::TableFull), Z_ERR_SYSTEM_OUT_OF_MEMORY);
    }

    /// The same table at a matching listener's door.
    #[test]
    fn each_refusal_of_a_matching_listener_answers_picos_code() {
        let at = |refusal| refusal_code(refusal, Door::MatchingListener);
        assert_eq!(at(Refusal::TableFull), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::KeyTooLong), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::NoEntityId), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(at(Refusal::Closed), Z_ERR_GENERIC);
        assert_eq!(at(Refusal::NotBuilt), ZEXT_ERR_UNSUPPORTED);
    }
}
