// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel's three objects over Mbed TLS: the library started on its arena ([`start`]), an
//! [`Identity`], and a [`Session`] over a byte [`Transport`].
//!
//! Single-threaded by contract, as the profile is: Mbed TLS keeps its PSA key store and its
//! arena in process-wide state with no lock, so every object here is neither `Send` nor `Sync`,
//! and a program starts the library once.

use core::cell::{OnceCell, UnsafeCell};
use core::ffi::{c_int, c_void, CStr};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ffi;

/// A zid derived from a key (decision D1): the first 16 bytes of SHA-256 over its DER
/// `SubjectPublicKeyInfo`.
pub type Zid = [u8; ffi::ZID_BYTES];

/// Why a channel call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// The transport under the session failed; the transport holds its reason.
    Transport,
    /// The peer finished the handshake without a certificate, so it proved no key.
    NoPeerCertificate,
    /// The arena had no room: worth a later try, once a session has ended.
    OutOfMemory,
    /// The library was started twice, or used before [`start`].
    State,
    /// Mbed TLS's or PSA's own code, negative.
    Code(i32),
}

impl TlsError {
    fn of(rc: c_int) -> Self {
        match rc {
            ffi::E_TRANSPORT => TlsError::Transport,
            ffi::E_NO_PEER_CERT => TlsError::NoPeerCertificate,
            ffi::E_STATE => TlsError::State,
            ffi::PSA_ERROR_INSUFFICIENT_MEMORY => TlsError::OutOfMemory,
            other => TlsError::Code(other),
        }
    }
}

/// `rc` when it is not an error.
fn check(rc: c_int) -> Result<c_int, TlsError> {
    if rc < 0 {
        Err(TlsError::of(rc))
    } else {
        Ok(rc)
    }
}

/// Start the library: every Mbed TLS allocation from here on comes from `arena`, and PSA Crypto
/// is initialised. Once per program; a second call is [`TlsError::State`].
pub fn start(arena: &'static mut [u8]) -> Result<(), TlsError> {
    // SAFETY: `arena` is writable for its length and lives for the program, and the library
    // keeps the only reference to it from here on (the slice is consumed).
    check(unsafe { ffi::wz_tls_start(arena.as_mut_ptr(), arena.len()) }).map(drop)
}

/// The static memory every Mbed TLS allocation of a program comes from. An image declares one
/// `static` (all zero bytes, so it costs no image size) and starts the library on it once
/// ([`Arena::start`]); the size is the image's budget for the channel, which
/// [`arena_peak`] measures.
pub struct Arena<const N: usize> {
    bytes: UnsafeCell<[u8; N]>,
    taken: AtomicBool,
}

// SAFETY: the bytes are handed out once, behind the `taken` flag, and from then on only the
// library (single-threaded by contract) touches them.
unsafe impl<const N: usize> Sync for Arena<N> {}

impl<const N: usize> Arena<N> {
    /// An arena of `N` zero bytes.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; N]),
            taken: AtomicBool::new(false),
        }
    }

    /// Start the library on this arena ([`start`]). A second start, on this arena or any other,
    /// is [`TlsError::State`].
    pub fn start(&'static self) -> Result<(), TlsError> {
        if self.taken.swap(true, Ordering::AcqRel) {
            return Err(TlsError::State);
        }
        // SAFETY: the flag above lets exactly one caller here, so this is the only reference to
        // the bytes that will ever exist, and they live for the program.
        start(unsafe { &mut *self.bytes.get() })
    }
}

/// Start the library on an allocator the platform already gave Mbed TLS (Zephyr starts one from
/// `CONFIG_MBEDTLS_HEAP_SIZE`): only PSA Crypto is initialised.
pub fn start_on_platform_arena() -> Result<(), TlsError> {
    // SAFETY: a null arena is the documented "already served" case.
    check(unsafe { ffi::wz_tls_start(ptr::null_mut(), 0) }).map(drop)
}

/// The arena's peak use since the last [`arena_peak_reset`], in bytes and in blocks, when the
/// build measures it.
pub fn arena_peak() -> Option<(usize, usize)> {
    let (mut bytes, mut blocks) = (0, 0);
    // SAFETY: both out-pointers are live.
    let rc = unsafe { ffi::wz_tls_arena_peak(&mut bytes, &mut blocks) };
    (rc == 0).then_some((bytes, blocks))
}

/// Restart the arena's peak from its current use.
pub fn arena_peak_reset() {
    // SAFETY: no argument; the library's own state.
    unsafe { ffi::wz_tls_arena_peak_reset() }
}

/// A device's identity: a P-256 key generated in the PSA key store (it never leaves it), a
/// certificate self-signed over the key, and the zid the key names.
pub struct Identity {
    raw: NonNull<ffi::Identity>,
}

impl Identity {
    /// A new identity whose certificate names `subject` (an X.509 name, `c"CN=..."`). The key is
    /// volatile: it lives until the identity is dropped.
    pub fn generate(subject: &CStr) -> Result<Self, TlsError> {
        let mut raw = ptr::null_mut();
        // SAFETY: `raw` is a live out-pointer and `subject` a NUL-terminated string.
        check(unsafe { ffi::wz_tls_identity_generate(&mut raw, subject.as_ptr()) })?;
        NonNull::new(raw)
            .map(|raw| Identity { raw })
            .ok_or(TlsError::State)
    }

    /// The zid this identity's key names.
    pub fn zid(&self) -> Zid {
        let mut zid = [0u8; ffi::ZID_BYTES];
        // SAFETY: a live identity and a 16-byte buffer.
        unsafe { ffi::wz_tls_identity_zid(self.raw.as_ptr(), zid.as_mut_ptr()) };
        zid
    }

    /// The certificate as PEM, each line handed to `line`: the block a router's operator copies
    /// into its configuration (a zenoh router's `root_ca_certificate`). Written with no
    /// allocation, for an image's console.
    pub fn certificate_pem(&self, mut line: impl FnMut(fmt::Arguments<'_>)) {
        line(format_args!("-----BEGIN CERTIFICATE-----"));
        // 48 bytes of DER are one 64-character line of base64, PEM's line length.
        for chunk in self.certificate_der().chunks(48) {
            line(format_args!("{}", Base64(chunk)));
        }
        line(format_args!("-----END CERTIFICATE-----"));
    }

    /// The certificate, DER: what a peer that pins by certificate (a zenoh router's
    /// `root_ca_certificate`) is given.
    pub fn certificate_der(&self) -> &[u8] {
        let (mut der, mut len) = (ptr::null(), 0);
        // SAFETY: a live identity and two live out-pointers; the bytes are the identity's and
        // live as long as it does, which the returned borrow states.
        unsafe {
            ffi::wz_tls_identity_cert(self.raw.as_ptr(), &mut der, &mut len);
            core::slice::from_raw_parts(der, len)
        }
    }
}

/// Bytes in standard base64 (RFC 4648, with padding).
struct Base64<'a>(&'a [u8]);

impl fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for group in self.0.chunks(3) {
            let b = [
                group[0],
                group.get(1).copied().unwrap_or(0),
                group.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= group.len() {
                    let index = (n >> (18 - 6 * i)) & 0x3f;
                    fmt::Write::write_char(f, char::from(ALPHABET[index as usize]))?;
                } else {
                    fmt::Write::write_char(f, '=')?;
                }
            }
        }
        Ok(())
    }
}

/// Where a program keeps its identity for as long as it runs: a `static` the image declares, made
/// once and lent for the program, which is the borrow a [`crate::stream::TlsDial`] holds.
pub struct IdentitySlot {
    cell: OnceCell<Identity>,
}

// SAFETY: single-threaded by contract, as the library is; the identity is written once and only
// read after.
unsafe impl Sync for IdentitySlot {}

impl IdentitySlot {
    /// An empty slot.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            cell: OnceCell::new(),
        }
    }

    /// Generate the program's identity ([`Identity::generate`]) into the slot and lend it. A
    /// second call is [`TlsError::State`]: a program has one identity.
    pub fn generate(&'static self, subject: &CStr) -> Result<&'static Identity, TlsError> {
        if self.cell.get().is_some() {
            return Err(TlsError::State);
        }
        let id = Identity::generate(subject)?;
        let _ = self.cell.set(id);
        self.cell.get().ok_or(TlsError::State)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // SAFETY: this identity's own pointer, freed once; a session borrowing it cannot outlive
        // it (`Session<'id, _>`).
        unsafe { ffi::wz_tls_identity_free(self.raw.as_ptr()) }
    }
}

/// What a transport call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Io {
    /// This many bytes were taken or read; a read of 0 is the end of the stream.
    Done(usize),
    /// Nothing can move now; the session reports it as wanting to read or write.
    WouldBlock,
    /// The transport failed. It keeps its reason; the session reports
    /// [`TlsError::Transport`].
    Failed,
}

/// The byte stream a session runs over.
pub trait Transport {
    /// Take up to `buf.len()` bytes.
    fn send(&self, buf: &[u8]) -> Io;
    /// Read up to `buf.len()` bytes.
    fn recv(&self, buf: &mut [u8]) -> Io;
}

unsafe extern "C" fn send_on<T: Transport>(ctx: *mut c_void, buf: *const u8, len: usize) -> c_int {
    // SAFETY: the session sets `ctx` to a live `&T` for the duration of the call that reaches
    // here (`Session::with_io`), and `buf` is readable for `len` bytes.
    let (io, buf) = unsafe { (&*(ctx as *const T), core::slice::from_raw_parts(buf, len)) };
    io_result(io.send(buf))
}

unsafe extern "C" fn recv_on<T: Transport>(ctx: *mut c_void, buf: *mut u8, len: usize) -> c_int {
    // SAFETY: as `send_on`, with `buf` writable for `len` bytes.
    let (io, buf) = unsafe {
        (
            &*(ctx as *const T),
            core::slice::from_raw_parts_mut(buf, len),
        )
    };
    io_result(io.recv(buf))
}

fn io_result(io: Io) -> c_int {
    match io {
        // A record is at most 2^14 bytes and its header, so a count always fits.
        Io::Done(n) => c_int::try_from(n).unwrap_or(c_int::MAX),
        Io::WouldBlock => ffi::IO_WOULD_BLOCK,
        Io::Failed => ffi::IO_FAILED,
    }
}

/// Which end of the handshake a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The end that dialled.
    Client,
    /// The end that accepted.
    Server,
}

/// A call that cannot finish until the transport moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// The call needs bytes from the peer.
    Read,
    /// The call needs the transport to take bytes.
    Write,
}

/// What a session call came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step<T> {
    /// Done, with this result.
    Done(T),
    /// Call again once the transport can move.
    Wait(Want),
}

/// A call's result: a count, a wait, or an error.
fn step(rc: c_int) -> Result<Step<usize>, TlsError> {
    match rc {
        ffi::WANT_READ => Ok(Step::Wait(Want::Read)),
        ffi::WANT_WRITE => Ok(Step::Wait(Want::Write)),
        rc => check(rc).map(|n| Step::Done(n as usize)),
    }
}

/// One TLS 1.3 session with mutual authentication, presenting the identity it borrows, over a
/// transport of type `T` each call is handed. No chain is the verdict: once the handshake is
/// done, [`Session::peer_zid`] is the zid of the key the peer proved, for the caller to pin.
pub struct Session<'id, T: Transport> {
    raw: NonNull<ffi::Session>,
    _own: PhantomData<&'id Identity>,
    _transport: PhantomData<fn(&T)>,
}

impl<'id, T: Transport> Session<'id, T> {
    /// A session of `role` presenting `own`.
    pub fn open(role: Role, own: &'id Identity) -> Result<Self, TlsError> {
        let io = ffi::Io {
            ctx: ptr::null_mut(),
            send: send_on::<T>,
            recv: recv_on::<T>,
        };
        let role = match role {
            Role::Client => ffi::CLIENT,
            Role::Server => ffi::SERVER,
        };
        let mut raw = ptr::null_mut();
        // SAFETY: a live out-pointer, a live identity the session's lifetime is tied to, and an
        // `Io` the library copies.
        check(unsafe { ffi::wz_tls_session_open(&mut raw, role, own.raw.as_ptr(), &io) })?;
        NonNull::new(raw)
            .map(|raw| Session {
                raw,
                _own: PhantomData,
                _transport: PhantomData,
            })
            .ok_or(TlsError::State)
    }

    /// Run `call` with the session pointed at `io`, and point it nowhere after: the transport
    /// is reached only from inside a call that holds it.
    fn with_io<R>(&mut self, io: &T, call: impl FnOnce(*mut ffi::Session) -> R) -> R {
        let s = self.raw.as_ptr();
        // SAFETY: a live session; `io` outlives the call below, and the context is cleared
        // before `io`'s borrow ends.
        unsafe { ffi::wz_tls_session_set_io_ctx(s, io as *const T as *mut c_void) };
        let out = call(s);
        // SAFETY: as above.
        unsafe { ffi::wz_tls_session_set_io_ctx(s, ptr::null_mut()) };
        out
    }

    /// Advance the handshake. Done once both ends proved their keys.
    pub fn handshake(&mut self, io: &T) -> Result<Step<()>, TlsError> {
        // SAFETY: a live session, pointed at a live transport.
        let rc = self.with_io(io, |s| unsafe { ffi::wz_tls_session_handshake(s) });
        step(rc).map(|done| match done {
            Step::Done(_) => Step::Done(()),
            Step::Wait(want) => Step::Wait(want),
        })
    }

    /// The zid of the key the peer's certificate carries, once the handshake is done.
    pub fn peer_zid(&self) -> Result<Zid, TlsError> {
        let mut zid = [0u8; ffi::ZID_BYTES];
        // SAFETY: a live session and a 16-byte buffer.
        check(unsafe { ffi::wz_tls_session_peer_zid(self.raw.as_ptr(), zid.as_mut_ptr()) })?;
        Ok(zid)
    }

    /// The negotiated cipher suite, once the handshake is done.
    pub fn suite(&self) -> Option<&'static CStr> {
        // SAFETY: a live session; the name is a string of the library's static suite table, or
        // null.
        let name = unsafe { ffi::wz_tls_session_suite(self.raw.as_ptr()) };
        // SAFETY: a non-null name is NUL-terminated and lives for the program.
        (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) })
    }

    /// Protect and send some of `buf`: how many bytes were taken.
    pub fn write(&mut self, io: &T, buf: &[u8]) -> Result<Step<usize>, TlsError> {
        // SAFETY: a live session pointed at a live transport, `buf` readable for its length.
        let rc = self.with_io(io, |s| unsafe {
            ffi::wz_tls_session_write(s, buf.as_ptr(), buf.len())
        });
        step(rc)
    }

    /// Read application data into `buf`: how many bytes, 0 when the peer ended the session.
    pub fn read(&mut self, io: &T, buf: &mut [u8]) -> Result<Step<usize>, TlsError> {
        // SAFETY: a live session pointed at a live transport, `buf` writable for its length.
        let rc = self.with_io(io, |s| unsafe {
            ffi::wz_tls_session_read(s, buf.as_mut_ptr(), buf.len())
        });
        step(rc)
    }

    /// Whether the session holds bytes a read returns without the transport.
    pub fn pending(&self) -> bool {
        // SAFETY: a live session; the call reads only its buffers.
        unsafe { ffi::wz_tls_session_pending(self.raw.as_ptr()) != 0 }
    }

    /// Tell the peer the session ends; best effort.
    pub fn close_notify(&mut self, io: &T) {
        // SAFETY: a live session pointed at a live transport.
        self.with_io(io, |s| unsafe { ffi::wz_tls_session_close_notify(s) });
    }
}

impl<T: Transport> Drop for Session<'_, T> {
    fn drop(&mut self) {
        // SAFETY: this session's own pointer, freed once.
        unsafe { ffi::wz_tls_session_free(self.raw.as_ptr()) }
    }
}
