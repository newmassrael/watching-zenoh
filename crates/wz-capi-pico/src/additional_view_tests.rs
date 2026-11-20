// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The additional library's view of this core, held to the core's own declarations.
//!
//! `wz-capi-pico-ext` compiles the doors of the additional features over
//! `crates/wz-capi-pico-ext/src/core_view.rs`: the C ABI of this core as the doors name it,
//! declared as a C program declares it and imported from the core library. Nothing there is
//! derived from the core, so this module compiles the same file into the core's tests and holds
//! every declaration to the core's: each type the doors allocate or read has the core's size,
//! alignment and field offsets, each constant the core's value, and each imported function the
//! core's signature, type for type through [`InCore`]. A function declared with another argument
//! or result does not compile here, and a type of another layout fails here, in the core's build,
//! and not as a corrupted stack in a program that loads the two libraries.

use core::mem::{align_of, offset_of, size_of};

// The view compiled into the core's tests, where only what this module names of it is used.
#[allow(dead_code)]
#[path = "../../wz-capi-pico-ext/src/core_view.rs"]
mod view;

/// What a type of the view is in the core: the type it stands for, and a compound type (a pointer,
/// an `Option`, a function pointer) made of the core's types where the view's are.
trait InCore {
    type Core;
}

/// The one relation of a type to itself, which a view's signature has with the core's when the
/// two are one.
trait Is<T> {}
impl<T> Is<T> for T {}

macro_rules! itself {
    ($($t:ty),* $(,)?) => {
        $(impl InCore for $t {
            type Core = $t;
        })*
    };
}

itself!(
    (),
    bool,
    u8,
    u16,
    u32,
    u64,
    i8,
    i32,
    usize,
    core::ffi::c_void
);

impl<T: InCore> InCore for *const T {
    type Core = *const T::Core;
}

impl<T: InCore> InCore for *mut T {
    type Core = *mut T::Core;
}

impl<T: InCore> InCore for Option<T> {
    type Core = Option<T::Core>;
}

macro_rules! fn_pointer {
    ($($arg:ident),*) => {
        impl<R: InCore $(, $arg: InCore)*> InCore for unsafe extern "C" fn($($arg),*) -> R {
            type Core = unsafe extern "C" fn($($arg::Core),*) -> R::Core;
        }
    };
}

fn_pointer!();
fn_pointer!(A);
fn_pointer!(A, B);
fn_pointer!(A, B, C);
fn_pointer!(A, B, C, D);
fn_pointer!(A, B, C, D, E);
fn_pointer!(A, B, C, D, E, F);

macro_rules! stands_for {
    ($($view:ty => $core:ty),* $(,)?) => {
        $(impl InCore for $view {
            type Core = $core;
        })*
    };
}

stands_for!(
    view::abi::z_owned_string_t => crate::abi::z_owned_string_t,
    view::abi::z_loaned_string_t => crate::abi::z_loaned_string_t,
    view::abi::z_view_string_t => crate::abi::z_view_string_t,
    view::abi::z_loaned_keyexpr_t => crate::abi::z_loaned_keyexpr_t,
    view::abi::z_view_keyexpr_t => crate::abi::z_view_keyexpr_t,
    view::abi::z_owned_bytes_t => crate::abi::z_owned_bytes_t,
    view::abi::z_loaned_bytes_t => crate::abi::z_loaned_bytes_t,
    view::abi::z_moved_bytes_t => crate::abi::z_moved_bytes_t,
    view::abi::z_moved_string_t => crate::abi::z_moved_string_t,
    view::session::z_loaned_session_t => crate::session::z_loaned_session_t,
    view::session::z_subscriber_options_t => crate::session::z_subscriber_options_t,
    view::ext_interface::wz_ext_interface_version_t => crate::ext_interface::wz_ext_interface_version_t,
    view::ext_interface::wz_ext_session_facts_t => crate::ext_interface::wz_ext_session_facts_t,
);

#[cfg(feature = "replay-cache")]
stands_for!(
    view::zid::z_id_t => crate::zid::z_id_t,
    view::pubsub::z_loaned_publisher_t => crate::pubsub::z_loaned_publisher_t,
    view::pubsub::z_publisher_put_options_t => crate::pubsub::z_publisher_put_options_t,
    view::pubsub::z_loaned_sample_t => crate::pubsub::z_loaned_sample_t,
    view::pubsub::z_owned_closure_sample_t => crate::pubsub::z_owned_closure_sample_t,
    view::pubsub::z_moved_closure_sample_t => crate::pubsub::z_moved_closure_sample_t,
    view::pubsub::z_owned_subscriber_t => crate::pubsub::z_owned_subscriber_t,
    view::pubsub::z_moved_subscriber_t => crate::pubsub::z_moved_subscriber_t,
    view::query::z_loaned_query_t => crate::query::z_loaned_query_t,
    view::query::z_owned_closure_query_t => crate::query::z_owned_closure_query_t,
    view::query::z_moved_closure_query_t => crate::query::z_moved_closure_query_t,
    view::query::z_owned_queryable_t => crate::query::z_owned_queryable_t,
    view::query::z_moved_queryable_t => crate::query::z_moved_queryable_t,
    view::query::z_queryable_options_t => crate::query::z_queryable_options_t,
    view::query::z_query_reply_options_t => crate::query::z_query_reply_options_t,
    view::get::z_loaned_reply_t => crate::get::z_loaned_reply_t,
    view::get::z_owned_closure_reply_t => crate::get::z_owned_closure_reply_t,
    view::get::z_moved_closure_reply_t => crate::get::z_moved_closure_reply_t,
    view::get::z_moved_encoding_t => crate::encoding::z_moved_encoding_t,
    view::get::z_query_consolidation_t => crate::get::z_query_consolidation_t,
    view::get::z_get_options_t => crate::get::z_get_options_t,
    view::decl_watch::wz_ext_decl_event_t => crate::decl_watch::wz_ext_decl_event_t,
    view::decl_watch::wz_ext_owned_decl_watch_t => crate::decl_watch::wz_ext_owned_decl_watch_t,
);

#[cfg(all(feature = "replay-cache", feature = "unstable-api"))]
stands_for!(
    view::get::z_source_info_t => crate::pubsub::z_source_info_t,
    view::get::z_moved_cancellation_token_t => crate::cancellation::z_moved_cancellation_token_t,
);

/// Compiles only when `view`'s type, read in the core's types, is `core`'s.
fn same<V: InCore, C>(_view: V, _core: C)
where
    V::Core: Is<C>,
{
}

/// The view's import of `$module::$name` and the core's export of it, as function pointers of the
/// arity the underscores give, held to one signature.
macro_rules! same_fn {
    ($module:ident :: $name:ident ($($arg:tt),*)) => {
        same(
            view::$module::$name as unsafe extern "C" fn($($arg),*) -> _,
            crate::$module::$name as unsafe extern "C" fn($($arg),*) -> _,
        )
    };
}

/// The view's type and the core's have one size and one alignment.
macro_rules! same_size {
    ($view:ty, $core:ty) => {
        assert_eq!(
            size_of::<$view>(),
            size_of::<$core>(),
            "the size of {}",
            stringify!($view)
        );
        assert_eq!(
            align_of::<$view>(),
            align_of::<$core>(),
            "the alignment of {}",
            stringify!($view)
        );
    };
}

/// Each named field is at the core's offset.
macro_rules! same_fields {
    ($view:ty, $core:ty; $($field:ident),* $(,)?) => {
        $(assert_eq!(
            offset_of!($view, $field),
            offset_of!($core, $field),
            "the offset of {}.{}",
            stringify!($view),
            stringify!($field)
        );)*
    };
}

#[test]
fn every_function_the_view_imports_has_the_core_s_signature() {
    same_fn!(bytes::z_bytes_copy_from_buf(_, _, _));
    same_fn!(bytes::z_bytes_move(_));
    same_fn!(bytes::z_internal_string_null(_));
    same_fn!(bytes::z_internal_string_check(_));
    same_fn!(bytes::z_string_loan(_));
    same_fn!(bytes::z_string_move(_));
    same_fn!(bytes::z_string_drop(_));
    same_fn!(bytes::z_string_copy_from_substr(_, _, _));
    same_fn!(bytes::z_string_data(_));
    same_fn!(bytes::z_string_len(_));
    same_fn!(keyexpr::z_keyexpr_as_view_string(_, _));
    same_fn!(keyexpr::z_view_keyexpr_empty(_));
    same_fn!(keyexpr::z_view_keyexpr_from_str(_, _));
    same_fn!(keyexpr::z_view_keyexpr_from_substr(_, _, _));
    same_fn!(keyexpr::z_view_keyexpr_loan(_));
    same_fn!(keyexpr::z_view_string_loan(_));
    same_fn!(ext_interface::wz_ext_interface_version(_));
    same_fn!(ext_interface::wz_ext_interface_major_1());
    same_fn!(ext_interface::wz_ext_interface_bytes_view(_, _, _));
    same_fn!(ext_interface::wz_ext_interface_run_in_callback(_, _));
    #[cfg(feature = "query")]
    same_fn!(ext_interface::wz_ext_interface_session_facts(_, _));
    #[cfg(feature = "event-ring")]
    same_fn!(event_log::wz_ext_event_emit(_, _, _, _));
}

#[cfg(feature = "replay-cache")]
#[test]
fn every_function_the_replay_doors_import_has_the_core_s_signature() {
    same_fn!(pubsub::z_closure_sample(_, _, _, _));
    same_fn!(pubsub::z_closure_sample_move(_));
    same_fn!(pubsub::z_declare_subscriber(_, _, _, _, _));
    same_fn!(pubsub::z_publisher_put(_, _, _));
    same_fn!(pubsub::z_sample_payload(_));
    same_fn!(pubsub::z_subscriber_move(_));
    same_fn!(pubsub::z_undeclare_subscriber(_));
    same_fn!(query::z_closure_query(_, _, _, _));
    same_fn!(query::z_closure_query_move(_));
    same_fn!(query::z_declare_queryable(_, _, _, _, _));
    same_fn!(query::z_query_keyexpr(_));
    same_fn!(query::z_query_reply(_, _, _, _));
    same_fn!(query::z_queryable_move(_));
    same_fn!(query::z_undeclare_queryable(_));
    same_fn!(get::z_closure_reply(_, _, _, _));
    same_fn!(get::z_closure_reply_move(_));
    same_fn!(get::z_get(_, _, _, _, _));
    same_fn!(get::z_get_options_default(_));
    same_fn!(get::z_reply_is_ok(_));
    same_fn!(get::z_reply_ok(_));
    same_fn!(get_to_peer::wz_ext_get_to_peer(_, _, _, _, _, _));
    same_fn!(decl_watch::wz_ext_decl_watch_declare(_, _, _, _, _, _));
    same_fn!(decl_watch::wz_ext_decl_watch_drop(_));
}

#[test]
fn every_value_the_doors_allocate_has_the_core_s_layout() {
    same_size!(view::abi::z_owned_string_t, crate::abi::z_owned_string_t);
    same_size!(view::abi::z_view_string_t, crate::abi::z_view_string_t);
    same_size!(view::abi::z_view_keyexpr_t, crate::abi::z_view_keyexpr_t);
    same_size!(view::abi::z_owned_bytes_t, crate::abi::z_owned_bytes_t);
    same_size!(
        view::ext_interface::wz_ext_interface_version_t,
        crate::ext_interface::wz_ext_interface_version_t
    );
    same_fields!(
        view::ext_interface::wz_ext_interface_version_t,
        crate::ext_interface::wz_ext_interface_version_t;
        struct_size, major, minor
    );
    same_size!(
        view::ext_interface::wz_ext_session_facts_t,
        crate::ext_interface::wz_ext_session_facts_t
    );
    same_fields!(
        view::ext_interface::wz_ext_session_facts_t,
        crate::ext_interface::wz_ext_session_facts_t;
        struct_size,
        closed,
        replay_reply_shape,
        replay_serve_holds_sends,
        replay_live_before_answer,
        targeted_query,
        reserved,
        querier_max_pending_queries,
    );
}

#[cfg(feature = "replay-cache")]
#[test]
fn every_value_the_replay_doors_allocate_has_the_core_s_layout() {
    same_size!(view::zid::z_id_t, crate::zid::z_id_t);
    same_fields!(view::zid::z_id_t, crate::zid::z_id_t; id);
    same_size!(
        view::pubsub::z_owned_closure_sample_t,
        crate::pubsub::z_owned_closure_sample_t
    );
    same_size!(
        view::pubsub::z_owned_subscriber_t,
        crate::pubsub::z_owned_subscriber_t
    );
    same_size!(
        view::query::z_owned_closure_query_t,
        crate::query::z_owned_closure_query_t
    );
    same_size!(
        view::query::z_owned_queryable_t,
        crate::query::z_owned_queryable_t
    );
    same_size!(
        view::get::z_owned_closure_reply_t,
        crate::get::z_owned_closure_reply_t
    );
    same_size!(
        view::get::z_query_consolidation_t,
        crate::get::z_query_consolidation_t
    );
    same_fields!(view::get::z_query_consolidation_t, crate::get::z_query_consolidation_t; mode);
    same_size!(view::get::z_get_options_t, crate::get::z_get_options_t);
    same_fields!(
        view::get::z_get_options_t,
        crate::get::z_get_options_t;
        payload,
        encoding,
        consolidation,
        congestion_control,
        priority,
        is_express,
        target,
        timeout_ms,
        attachment,
        accept_replies,
    );
    #[cfg(feature = "local-queryable")]
    same_fields!(view::get::z_get_options_t, crate::get::z_get_options_t; allowed_destination);
    #[cfg(feature = "unstable-api")]
    same_fields!(
        view::get::z_get_options_t,
        crate::get::z_get_options_t;
        source_info,
        cancellation_token
    );
    same_size!(
        view::decl_watch::wz_ext_decl_event_t,
        crate::decl_watch::wz_ext_decl_event_t
    );
    same_fields!(
        view::decl_watch::wz_ext_decl_event_t,
        crate::decl_watch::wz_ext_decl_event_t;
        kind,
        entity,
        zid_len,
        reserved,
        reserved2,
        id,
        keyexpr,
        keyexpr_len,
        zid,
    );
    same_size!(
        view::decl_watch::wz_ext_owned_decl_watch_t,
        crate::decl_watch::wz_ext_owned_decl_watch_t
    );
    same_fields!(
        view::decl_watch::wz_ext_owned_decl_watch_t,
        crate::decl_watch::wz_ext_owned_decl_watch_t;
        _val
    );
}

#[test]
fn every_constant_the_view_states_is_the_core_s() {
    use crate::ext_interface as core_ext;
    use view::ext_interface as view_ext;

    assert_eq!(
        view_ext::WZ_EXT_INTERFACE_MAJOR,
        core_ext::WZ_EXT_INTERFACE_MAJOR
    );
    assert_eq!(
        view_ext::WZ_EXT_INTERFACE_MINOR,
        core_ext::WZ_EXT_INTERFACE_MINOR
    );
    assert_eq!(
        view_ext::WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE,
        core_ext::WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE
    );
    assert_eq!(
        view_ext::WZ_EXT_REPLAY_SHAPE_SEGMENTED,
        core_ext::WZ_EXT_REPLAY_SHAPE_SEGMENTED
    );
    assert_eq!(
        view_ext::WZ_EXT_REPLAY_LIVE_DELIVER,
        core_ext::WZ_EXT_REPLAY_LIVE_DELIVER
    );
    assert_eq!(
        view_ext::WZ_EXT_REPLAY_LIVE_HOLD_BACK,
        core_ext::WZ_EXT_REPLAY_LIVE_HOLD_BACK
    );
}

#[cfg(feature = "event-ring")]
#[test]
fn every_event_constant_the_view_states_is_the_core_s() {
    use crate::event_log as core_log;
    use view::event_log as view_log;

    assert_eq!(
        view_log::WZ_EXT_EVENT_LEVEL_LIBRARY,
        core_log::WZ_EXT_EVENT_LEVEL_LIBRARY
    );
    assert_eq!(
        view_log::WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED,
        core_log::WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED
    );
    assert_eq!(
        view_log::WZ_EXT_EVENT_INSTANCE_KEY_UNDECODABLE,
        core_log::WZ_EXT_EVENT_INSTANCE_KEY_UNDECODABLE
    );
    assert_eq!(
        view_log::WZ_EXT_EVENT_INSTANCE_KEY_ABSENT,
        core_log::WZ_EXT_EVENT_INSTANCE_KEY_ABSENT
    );
    assert_eq!(
        view_log::WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED,
        core_log::WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED
    );
}

#[cfg(feature = "replay-cache")]
#[test]
fn every_constant_the_replay_doors_read_is_the_core_s() {
    assert_eq!(view::zid::Z_ID_SIZE, crate::zid::Z_ID_SIZE);
    assert_eq!(
        view::get::Z_CONSOLIDATION_MODE_NONE,
        crate::get::Z_CONSOLIDATION_MODE_NONE
    );
    assert_eq!(
        view::get::Z_QUERY_TARGET_ALL,
        crate::get::Z_QUERY_TARGET_ALL
    );
    assert_eq!(
        view::decl_watch::WZ_EXT_DECL_DECLARED,
        crate::decl_watch::WZ_EXT_DECL_DECLARED
    );
    assert_eq!(
        view::decl_watch::WZ_EXT_DECL_UNDECLARED,
        crate::decl_watch::WZ_EXT_DECL_UNDECLARED
    );
    assert_eq!(
        view::decl_watch::WZ_EXT_DECL_QUERYABLE,
        crate::decl_watch::WZ_EXT_DECL_QUERYABLE
    );
}

/// The view answers through the core: the function named by the major version, imported by its
/// C name, is the core's own.
#[test]
fn the_view_s_import_of_the_major_version_reaches_the_core() {
    // SAFETY: an import of a function that takes nothing and reads a constant.
    let imported = unsafe { view::ext_interface::wz_ext_interface_major_1() };
    assert_eq!(imported, crate::ext_interface::wz_ext_interface_major_1());
}
