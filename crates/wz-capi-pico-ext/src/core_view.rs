// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The core of the pico C ABI as the doors of the additional features see it from a library of
//! their own: the items of its C ABI and of the extension interface that they name, declared the
//! way a C program declares them from the headers, and imported from the core library through C.
//!
//! Each module has the name of the core module the doors name it by (`crate::bytes`,
//! `crate::ext_interface`, ...), so the doors' sources compile unchanged over it. Nothing here is
//! defined: a function is an import, and a type is one the core writes and reads, the program's
//! storage of the core's size. A type the doors only point at is a type of no size here, and a
//! type they allocate is as many words as the core's, so the doors hold the core's values as the
//! program does and never look inside them; the fields of a type are declared only where the doors
//! read or write them, as the C header declares them.
//!
//! Each block of imports names the core library it imports from on Windows, where a DLL resolves
//! its imports when it is linked: `raw-dylib`, so the import is made from the DLL's name and needs
//! no import library, and by the undecorated name on 32-bit Windows, which is how the core exports
//! its C functions there. Elsewhere the build script names the core (`build.rs`). In the core's
//! tests (`cfg(test)`) no block names a library: the imports resolve to the core's own exports in
//! the test executable.
//!
//! The core's own tests compile this file against the core
//! (`crates/wz-capi-pico/src/additional_view_tests.rs`) and hold each declaration to the core's:
//! the size, alignment and field offsets of each type, the value of each constant and the
//! signature of each function. A declaration that drifts from the core fails there, in the core's
//! own build, and not in a program.

/// Types of the core's values (`crate::abi`).
pub mod abi {
    /// An owned string (pico `z_owned_string_t`), four words of the core's.
    #[repr(C)]
    pub struct z_owned_string_t {
        _opaque: [*mut core::ffi::c_void; 4],
    }

    /// A loaned string (pico `z_loaned_string_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_string_t {
        _opaque: [u8; 0],
    }

    /// A string view (pico `z_view_string_t`), four words of the core's.
    #[repr(C)]
    pub struct z_view_string_t {
        _opaque: [*mut core::ffi::c_void; 4],
    }

    /// A loaned key expression (pico `z_loaned_keyexpr_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_keyexpr_t {
        _opaque: [u8; 0],
    }

    /// A key expression view (pico `z_view_keyexpr_t`), six words of the core's.
    #[repr(C)]
    pub struct z_view_keyexpr_t {
        _opaque: [*mut core::ffi::c_void; 6],
    }

    /// An owned payload (pico `z_owned_bytes_t`), four words of the core's.
    #[repr(C)]
    pub struct z_owned_bytes_t {
        _opaque: [*mut core::ffi::c_void; 4],
    }

    /// A loaned payload (pico `z_loaned_bytes_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_bytes_t {
        _opaque: [u8; 0],
    }

    /// A moved payload (pico `z_moved_bytes_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_bytes_t {
        _opaque: [u8; 0],
    }
}

/// The session the doors are handed (`crate::session`).
pub mod session {
    /// A loaned session (pico `z_loaned_session_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_session_t {
        _opaque: [u8; 0],
    }

    /// A subscriber's options (pico `z_subscriber_options_t`), only pointed at.
    #[repr(C)]
    pub struct z_subscriber_options_t {
        _opaque: [u8; 0],
    }
}

/// The payloads and strings the doors make and read (`crate::bytes`).
pub mod bytes {
    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn z_bytes_copy_from_buf(
            bytes: *mut super::abi::z_owned_bytes_t,
            data: *const u8,
            len: usize,
        ) -> crate::result::ZResult;
        pub fn z_bytes_move(
            bytes: *mut super::abi::z_owned_bytes_t,
        ) -> *mut super::abi::z_moved_bytes_t;
        pub fn z_internal_string_null(string: *mut super::abi::z_owned_string_t);
        pub fn z_string_copy_from_substr(
            string: *mut super::abi::z_owned_string_t,
            value: *const core::ffi::c_char,
            len: usize,
        ) -> crate::result::ZResult;
        pub fn z_string_data(
            string: *const super::abi::z_loaned_string_t,
        ) -> *const core::ffi::c_char;
        pub fn z_string_len(string: *const super::abi::z_loaned_string_t) -> usize;
    }
}

/// The key expressions the doors make and read (`crate::keyexpr`).
pub mod keyexpr {
    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn z_keyexpr_as_view_string(
            keyexpr: *const super::abi::z_loaned_keyexpr_t,
            string: *mut super::abi::z_view_string_t,
        ) -> crate::result::ZResult;
        pub fn z_view_keyexpr_from_substr(
            keyexpr: *mut super::abi::z_view_keyexpr_t,
            name: *const core::ffi::c_char,
            len: usize,
        ) -> crate::result::ZResult;
        pub fn z_view_keyexpr_loan(
            keyexpr: *const super::abi::z_view_keyexpr_t,
        ) -> *const super::abi::z_loaned_keyexpr_t;
        pub fn z_view_string_loan(
            string: *const super::abi::z_view_string_t,
        ) -> *const super::abi::z_loaned_string_t;
    }
}

/// The versioned extension interface (`crate::ext_interface`).
pub mod ext_interface {
    /// The major version of the interface these doors were written against.
    pub const WZ_EXT_INTERFACE_MAJOR: u16 = 1;
    /// The minor version of the interface these doors were written against.
    pub const WZ_EXT_INTERFACE_MINOR: u16 = 0;

    /// `replay_reply_shape`: one reply per frame, as it was sent.
    pub const WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE: u8 = 0;
    /// `replay_reply_shape`: each frame as the pieces of its segment profile.
    pub const WZ_EXT_REPLAY_SHAPE_SEGMENTED: u8 = 1;
    /// `replay_live_before_answer`: a live sample is handed on as it arrives.
    pub const WZ_EXT_REPLAY_LIVE_DELIVER: u8 = 0;
    /// `replay_live_before_answer`: live samples wait for the first round.
    pub const WZ_EXT_REPLAY_LIVE_HOLD_BACK: u8 = 1;

    /// The version of the interface (`wz_ext_interface_version_t`).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct wz_ext_interface_version_t {
        pub struct_size: u32,
        pub major: u16,
        pub minor: u16,
    }

    /// What the core says of a session (`wz_ext_session_facts_t`).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct wz_ext_session_facts_t {
        pub struct_size: u32,
        pub closed: u8,
        pub replay_reply_shape: u8,
        pub replay_serve_holds_sends: u8,
        pub replay_live_before_answer: u8,
        pub targeted_query: u8,
        pub reserved: [u8; 7],
        pub querier_max_pending_queries: usize,
    }

    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn wz_ext_interface_version(
            out: *mut wz_ext_interface_version_t,
        ) -> crate::result::ZResult;
        pub fn wz_ext_interface_major_1() -> u16;
        #[cfg(feature = "query")]
        pub fn wz_ext_interface_session_facts(
            session: *const super::session::z_loaned_session_t,
            out: *mut wz_ext_session_facts_t,
        ) -> crate::result::ZResult;
        pub fn wz_ext_interface_bytes_view(
            bytes: *const super::abi::z_loaned_bytes_t,
            data: *mut *const u8,
            len: *mut usize,
        ) -> crate::result::ZResult;
        pub fn wz_ext_interface_run_in_callback(
            body: Option<unsafe extern "C" fn(context: *mut core::ffi::c_void)>,
            context: *mut core::ffi::c_void,
        ) -> crate::result::ZResult;
    }
}

/// The node's event log, which the instance keys report to (`crate::event_log`).
#[cfg(feature = "event-ring")]
pub mod event_log {
    /// `level` of an event the library reports.
    pub const WZ_EXT_EVENT_LEVEL_LIBRARY: u8 = 255;
    /// `source` of an event that says an instance key dropped a sample.
    pub const WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED: u16 = 0xFF02;
    /// The first argument of that event: the key field did not decode.
    pub const WZ_EXT_EVENT_INSTANCE_KEY_UNDECODABLE: u64 = 0;
    /// The first argument of that event: the key field is absent.
    pub const WZ_EXT_EVENT_INSTANCE_KEY_ABSENT: u64 = 1;
    /// The first argument of that event: the key is not one the program listed.
    pub const WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED: u64 = 2;

    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn wz_ext_event_emit(
            level: u8,
            source: u16,
            args: *const u64,
            arg_count: usize,
        ) -> crate::result::ZResult;
    }
}

/// The ids of the peers of a session (`crate::zid`).
#[cfg(feature = "replay-cache")]
pub mod zid {
    /// The bytes of a zenoh id.
    pub const Z_ID_SIZE: usize = 16;

    /// A zenoh id (pico `z_id_t`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct z_id_t {
        pub id: [u8; Z_ID_SIZE],
    }
}

/// The publisher and the subscriber the replay doors drive (`crate::pubsub`).
#[cfg(feature = "replay-cache")]
pub mod pubsub {
    /// A loaned publisher (pico `z_loaned_publisher_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_publisher_t {
        _opaque: [u8; 0],
    }

    /// A publisher put's options (pico `z_publisher_put_options_t`), only pointed at.
    #[repr(C)]
    pub struct z_publisher_put_options_t {
        _opaque: [u8; 0],
    }

    /// A loaned sample (pico `z_loaned_sample_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_sample_t {
        _opaque: [u8; 0],
    }

    /// An owned sample closure (pico `z_owned_closure_sample_t`), three words of the core's.
    #[repr(C)]
    pub struct z_owned_closure_sample_t {
        _opaque: [*mut core::ffi::c_void; 3],
    }

    /// A moved sample closure (pico `z_moved_closure_sample_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_closure_sample_t {
        _opaque: [u8; 0],
    }

    /// An owned subscriber (pico `z_owned_subscriber_t`), four words of the core's.
    #[repr(C)]
    pub struct z_owned_subscriber_t {
        _opaque: [*mut core::ffi::c_void; 4],
    }

    /// A moved subscriber (pico `z_moved_subscriber_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_subscriber_t {
        _opaque: [u8; 0],
    }

    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn z_closure_sample(
            closure: *mut z_owned_closure_sample_t,
            call: Option<
                unsafe extern "C" fn(
                    sample: *const z_loaned_sample_t,
                    context: *mut core::ffi::c_void,
                ),
            >,
            drop: Option<unsafe extern "C" fn(context: *mut core::ffi::c_void)>,
            context: *mut core::ffi::c_void,
        ) -> crate::result::ZResult;
        pub fn z_closure_sample_move(
            closure: *mut z_owned_closure_sample_t,
        ) -> *mut z_moved_closure_sample_t;
        pub fn z_declare_subscriber(
            session: *const super::session::z_loaned_session_t,
            subscriber: *mut z_owned_subscriber_t,
            keyexpr: *const super::abi::z_loaned_keyexpr_t,
            callback: *mut z_moved_closure_sample_t,
            options: *const super::session::z_subscriber_options_t,
        ) -> crate::result::ZResult;
        pub fn z_publisher_put(
            publisher: *const z_loaned_publisher_t,
            payload: *mut super::abi::z_moved_bytes_t,
            options: *const z_publisher_put_options_t,
        ) -> crate::result::ZResult;
        pub fn z_sample_payload(
            sample: *const z_loaned_sample_t,
        ) -> *const super::abi::z_loaned_bytes_t;
        pub fn z_subscriber_move(
            subscriber: *mut z_owned_subscriber_t,
        ) -> *mut z_moved_subscriber_t;
        pub fn z_undeclare_subscriber(
            subscriber: *mut z_moved_subscriber_t,
        ) -> crate::result::ZResult;
    }
}

/// The queryable the replay publisher answers through (`crate::query`).
#[cfg(feature = "replay-cache")]
pub mod query {
    /// A loaned query (pico `z_loaned_query_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_query_t {
        _opaque: [u8; 0],
    }

    /// An owned query closure (pico `z_owned_closure_query_t`), three words of the core's.
    #[repr(C)]
    pub struct z_owned_closure_query_t {
        _opaque: [*mut core::ffi::c_void; 3],
    }

    /// A moved query closure (pico `z_moved_closure_query_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_closure_query_t {
        _opaque: [u8; 0],
    }

    /// An owned queryable (pico `z_owned_queryable_t`), four words of the core's.
    #[repr(C)]
    pub struct z_owned_queryable_t {
        _opaque: [*mut core::ffi::c_void; 4],
    }

    /// A moved queryable (pico `z_moved_queryable_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_queryable_t {
        _opaque: [u8; 0],
    }

    /// A queryable's options (pico `z_queryable_options_t`), only pointed at.
    #[repr(C)]
    pub struct z_queryable_options_t {
        _opaque: [u8; 0],
    }

    /// A reply's options (pico `z_query_reply_options_t`), only pointed at.
    #[repr(C)]
    pub struct z_query_reply_options_t {
        _opaque: [u8; 0],
    }

    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn z_closure_query(
            closure: *mut z_owned_closure_query_t,
            call: Option<
                unsafe extern "C" fn(
                    query: *const z_loaned_query_t,
                    context: *mut core::ffi::c_void,
                ),
            >,
            drop: Option<unsafe extern "C" fn(context: *mut core::ffi::c_void)>,
            context: *mut core::ffi::c_void,
        ) -> crate::result::ZResult;
        pub fn z_closure_query_move(
            closure: *mut z_owned_closure_query_t,
        ) -> *mut z_moved_closure_query_t;
        pub fn z_declare_queryable(
            session: *const super::session::z_loaned_session_t,
            queryable: *mut z_owned_queryable_t,
            keyexpr: *const super::abi::z_loaned_keyexpr_t,
            callback: *mut z_moved_closure_query_t,
            options: *const z_queryable_options_t,
        ) -> crate::result::ZResult;
        pub fn z_query_keyexpr(
            query: *const z_loaned_query_t,
        ) -> *const super::abi::z_loaned_keyexpr_t;
        pub fn z_query_reply(
            query: *const z_loaned_query_t,
            keyexpr: *const super::abi::z_loaned_keyexpr_t,
            payload: *mut super::abi::z_moved_bytes_t,
            options: *const z_query_reply_options_t,
        ) -> crate::result::ZResult;
        pub fn z_queryable_move(queryable: *mut z_owned_queryable_t) -> *mut z_moved_queryable_t;
        pub fn z_undeclare_queryable(queryable: *mut z_moved_queryable_t)
            -> crate::result::ZResult;
    }
}

/// The get the replay subscriber asks (`crate::get`).
#[cfg(feature = "replay-cache")]
pub mod get {
    /// `z_query_consolidation_t.mode`: every reply, none merged.
    pub const Z_CONSOLIDATION_MODE_NONE: core::ffi::c_int = 0;
    /// `z_get_options_t.target`: every queryable that matches.
    pub const Z_QUERY_TARGET_ALL: core::ffi::c_int = 1;

    /// A loaned reply (pico `z_loaned_reply_t`), only pointed at.
    #[repr(C)]
    pub struct z_loaned_reply_t {
        _opaque: [u8; 0],
    }

    /// An owned reply closure (pico `z_owned_closure_reply_t`), three words of the core's.
    #[repr(C)]
    pub struct z_owned_closure_reply_t {
        _opaque: [*mut core::ffi::c_void; 3],
    }

    /// A moved reply closure (pico `z_moved_closure_reply_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_closure_reply_t {
        _opaque: [u8; 0],
    }

    /// A moved encoding (pico `z_moved_encoding_t`), only pointed at.
    #[repr(C)]
    pub struct z_moved_encoding_t {
        _opaque: [u8; 0],
    }

    /// A source info (pico `z_source_info_t`), only pointed at.
    #[cfg(feature = "unstable-api")]
    #[repr(C)]
    pub struct z_source_info_t {
        _opaque: [u8; 0],
    }

    /// A moved cancellation token (pico `z_moved_cancellation_token_t`), only pointed at.
    #[cfg(feature = "unstable-api")]
    #[repr(C)]
    pub struct z_moved_cancellation_token_t {
        _opaque: [u8; 0],
    }

    /// The consolidation of a get (pico `z_query_consolidation_t`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct z_query_consolidation_t {
        pub mode: core::ffi::c_int,
    }

    /// A get's options (pico `z_get_options_t`), whose fields the replay subscriber sets after
    /// `z_get_options_default`: its layout is the arm's, the unstable API's two fields and the
    /// local queryable's one present as the core's build has them.
    #[repr(C)]
    pub struct z_get_options_t {
        pub payload: *mut super::abi::z_moved_bytes_t,
        pub encoding: *mut z_moved_encoding_t,
        pub consolidation: z_query_consolidation_t,
        pub congestion_control: core::ffi::c_int,
        pub priority: core::ffi::c_int,
        pub is_express: bool,
        #[cfg(feature = "local-queryable")]
        pub allowed_destination: core::ffi::c_int,
        pub target: core::ffi::c_int,
        pub timeout_ms: u64,
        pub attachment: *mut super::abi::z_moved_bytes_t,
        #[cfg(feature = "unstable-api")]
        pub source_info: *mut z_source_info_t,
        #[cfg(feature = "unstable-api")]
        pub cancellation_token: *mut z_moved_cancellation_token_t,
        pub accept_replies: core::ffi::c_int,
    }

    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn z_closure_reply(
            closure: *mut z_owned_closure_reply_t,
            call: Option<
                unsafe extern "C" fn(reply: *mut z_loaned_reply_t, context: *mut core::ffi::c_void),
            >,
            drop: Option<unsafe extern "C" fn(context: *mut core::ffi::c_void)>,
            context: *mut core::ffi::c_void,
        ) -> crate::result::ZResult;
        pub fn z_closure_reply_move(
            closure: *mut z_owned_closure_reply_t,
        ) -> *mut z_moved_closure_reply_t;
        pub fn z_get(
            session: *const super::session::z_loaned_session_t,
            keyexpr: *const super::abi::z_loaned_keyexpr_t,
            parameters: *const core::ffi::c_char,
            callback: *mut z_moved_closure_reply_t,
            options: *mut z_get_options_t,
        ) -> crate::result::ZResult;
        pub fn z_get_options_default(options: *mut z_get_options_t);
        pub fn z_reply_is_ok(reply: *const z_loaned_reply_t) -> bool;
        pub fn z_reply_ok(
            reply: *const z_loaned_reply_t,
        ) -> *const super::pubsub::z_loaned_sample_t;
    }
}

/// A get addressed to one node (`crate::get_to_peer`).
#[cfg(feature = "replay-cache")]
pub mod get_to_peer {
    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn wz_ext_get_to_peer(
            session: *const super::session::z_loaned_session_t,
            keyexpr: *const super::abi::z_loaned_keyexpr_t,
            parameters: *const core::ffi::c_char,
            callback: *mut super::get::z_moved_closure_reply_t,
            options: *mut super::get::z_get_options_t,
            peer: *const super::zid::z_id_t,
        ) -> crate::result::ZResult;
    }
}

/// What the peers of a session declare, which the replay subscriber watches
/// (`crate::decl_watch`).
#[cfg(feature = "replay-cache")]
pub mod decl_watch {
    /// `kind` of an event: the peer declared the entity.
    pub const WZ_EXT_DECL_DECLARED: u8 = 0;
    /// `kind` of an event: the peer retracted the entity.
    pub const WZ_EXT_DECL_UNDECLARED: u8 = 1;
    /// `entity` of a watch and an event: a queryable.
    pub const WZ_EXT_DECL_QUERYABLE: u8 = 1;

    /// One declaration or retraction a watch is told (`wz_ext_decl_event_t`).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct wz_ext_decl_event_t {
        pub kind: u8,
        pub entity: u8,
        pub zid_len: u8,
        pub reserved: u8,
        pub reserved2: u32,
        pub id: u64,
        pub keyexpr: *const core::ffi::c_char,
        pub keyexpr_len: usize,
        pub zid: [u8; wz_session_core::session_zid::ZID_MAX],
    }

    /// An owned watch (`wz_ext_owned_decl_watch_t`).
    #[repr(C)]
    pub struct wz_ext_owned_decl_watch_t {
        pub _val: *mut core::ffi::c_void,
    }

    #[cfg_attr(
        all(not(test), windows, target_arch = "x86"),
        link(
            name = "wz_capi_pico",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        all(not(test), windows, not(target_arch = "x86")),
        link(name = "wz_capi_pico", kind = "raw-dylib")
    )]
    extern "C" {
        pub fn wz_ext_decl_watch_declare(
            session: *const super::session::z_loaned_session_t,
            watch: *mut wz_ext_owned_decl_watch_t,
            entity: u8,
            call: Option<
                unsafe extern "C" fn(
                    context: *mut core::ffi::c_void,
                    event: *const wz_ext_decl_event_t,
                ),
            >,
            drop: Option<unsafe extern "C" fn(context: *mut core::ffi::c_void)>,
            context: *mut core::ffi::c_void,
        ) -> crate::result::ZResult;
        pub fn wz_ext_decl_watch_drop(watch: *mut wz_ext_owned_decl_watch_t);
    }
}
