// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The calls of `csrc/wz_tls.h`, declared by hand: every argument is a scalar, a pointer or
//! the one plain struct [`Io`], so no Mbed TLS layout crosses into Rust.

use core::ffi::{c_char, c_int, c_void};
use core::marker::{PhantomData, PhantomPinned};

pub const ZID_BYTES: usize = 16;

pub const WANT_READ: c_int = -0x10010;
pub const WANT_WRITE: c_int = -0x10011;

pub const E_TRANSPORT: c_int = -0x10001;
pub const E_NO_PEER_CERT: c_int = -0x10002;
pub const E_STATE: c_int = -0x10003;
pub const E_NO_TRUST: c_int = -0x10004;

pub const IO_WOULD_BLOCK: c_int = -1;
pub const IO_FAILED: c_int = -2;

pub const CLIENT: c_int = 0;
pub const SERVER: c_int = 1;

/// PSA's "insufficient memory", which Mbed TLS also returns for a failed allocation
/// (`MBEDTLS_ERR_SSL_ALLOC_FAILED` is defined as it).
pub const PSA_ERROR_INSUFFICIENT_MEMORY: c_int = -141;

/// `struct wz_tls_identity`, only ever behind a pointer.
#[repr(C)]
pub struct Identity {
    _opaque: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `struct wz_tls_trust`, only ever behind a pointer.
#[repr(C)]
pub struct Trust {
    _opaque: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `struct wz_tls_session`, only ever behind a pointer.
#[repr(C)]
pub struct Session {
    _opaque: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `struct wz_tls_io`.
#[repr(C)]
pub struct Io {
    pub ctx: *mut c_void,
    pub send: unsafe extern "C" fn(ctx: *mut c_void, buf: *const u8, len: usize) -> c_int,
    pub recv: unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize) -> c_int,
}

extern "C" {
    pub fn wz_tls_start(arena: *mut u8, len: usize) -> c_int;
    pub fn wz_tls_arena_peak(bytes: *mut usize, blocks: *mut usize) -> c_int;
    pub fn wz_tls_arena_peak_reset();

    pub fn wz_tls_identity_generate(out: *mut *mut Identity, subject: *const c_char) -> c_int;
    pub fn wz_tls_identity_zid(id: *const Identity, zid: *mut u8);
    pub fn wz_tls_identity_cert(id: *const Identity, der: *mut *const u8, len: *mut usize);
    pub fn wz_tls_identity_from_pem(
        out: *mut *mut Identity,
        chain: *const u8,
        chain_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> c_int;
    pub fn wz_tls_identity_free(id: *mut Identity);

    pub fn wz_tls_trust_from_pem(
        out: *mut *mut Trust,
        roots: *const u8,
        len: usize,
        check_dates: c_int,
        now: i64,
    ) -> c_int;
    pub fn wz_tls_trust_free(trust: *mut Trust);

    pub fn wz_tls_session_open_chain(
        out: *mut *mut Session,
        role: c_int,
        own: *const Identity,
        trust: *const Trust,
        server_name: *const c_char,
        io: *const Io,
    ) -> c_int;

    pub fn wz_tls_session_open(
        out: *mut *mut Session,
        role: c_int,
        own: *const Identity,
        io: *const Io,
    ) -> c_int;
    pub fn wz_tls_session_set_io_ctx(s: *mut Session, ctx: *mut c_void);
    pub fn wz_tls_session_handshake(s: *mut Session) -> c_int;
    pub fn wz_tls_session_peer_zid(s: *const Session, zid: *mut u8) -> c_int;
    pub fn wz_tls_session_suite(s: *const Session) -> *const c_char;
    pub fn wz_tls_session_write(s: *mut Session, buf: *const u8, len: usize) -> c_int;
    pub fn wz_tls_session_read(s: *mut Session, buf: *mut u8, len: usize) -> c_int;
    pub fn wz_tls_session_pending(s: *const Session) -> c_int;
    pub fn wz_tls_session_close_notify(s: *mut Session);
    pub fn wz_tls_session_free(s: *mut Session);
}
