// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_transport_*`: a transport the program supplies. A program with a network stack of its
//! own gives the session that stack in place of the system's sockets: a `send` the session calls
//! with bytes, and calls the program makes when bytes arrive or a link changes state.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `app-transport` capability implies `unstable-api`.
//!
//! The transport object is engine-neutral (`wz_session_core::app_transport`), its table held
//! under the port's lock, and the links over it are the engine's: the tokio engine's
//! (`wz_runtime_tokio::app_link`) or the cooperative engine's (`wz_runtime_coop::app_link`),
//! whichever the build has. This file is the pico ABI's names, result codes and ownership around
//! them, and the port that turns the program's function pointers into the calls the engine makes.
//!
//! # Who owns the transport
//!
//! The program makes the transport (`wz_ext_transport_new`) and holds it, and the calls it makes
//! name it. Not the config: a config that dials makes `z_open` wait for the handshake, whose bytes
//! the program hands in through `wz_ext_transport_received` from its own thread WHILE `z_open`
//! runs, so the program needs the object before the session exists and apart from the config,
//! which `z_open` consumes. `wz_ext_config_transport` gives a config a reference to it; the
//! session opened from that config holds one for as long as it has a link; the program's own
//! drops when it drops it. The program's `drop(context)` runs once, when the last of them goes.
//!
//! # Handles
//!
//! The session names every link: `open` is handed the handle of the link it opens, which is in
//! the transport's table before `open` is called, so a program that reports the link up from its
//! own thread before `open` returns finds it. A stream the program accepts on a listener is named
//! by `wz_ext_transport_accepted`, which returns its handle. A handle is never reused.

use core::ffi::{c_char, c_void, CStr};
use std::sync::Arc;

use wz_session_core::app_link_table::AppLinkTable;
use wz_session_core::app_link_table::{
    AppLinkKind, InboundRefusal, LinkHandle, ProgramEvent, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{AppPort, AppTransport, TableLock};

use crate::abi::z_loaned_config_t;
use crate::config::ConfigState;
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ERR_NULL, Z_OK};

/// A link of a transport the program supplies. 0 never names one.
pub type wz_ext_link_t = u64;

/// What kind of link `open` is asked for.
pub type wz_ext_link_kind_t = u8;
/// A byte stream the session dials (a `tcp/` connect locator).
pub const WZ_EXT_LINK_STREAM_DIAL: wz_ext_link_kind_t = AppLinkKind::StreamDial as u8;
/// A stream listener (a `tcp/` listen locator).
pub const WZ_EXT_LINK_STREAM_LISTEN: wz_ext_link_kind_t = AppLinkKind::StreamListen as u8;
/// A unicast datagram link (a `udp/` connect locator).
pub const WZ_EXT_LINK_DATAGRAM: wz_ext_link_kind_t = AppLinkKind::Datagram as u8;
/// A multicast group (a `udp/` listen locator with `#iface=`).
pub const WZ_EXT_LINK_GROUP: wz_ext_link_kind_t = AppLinkKind::Group as u8;
/// A datagram listener (a `udp/` listen locator naming no interface): the program accepts each
/// source that sends to it with `wz_ext_transport_accepted`.
pub const WZ_EXT_LINK_DATAGRAM_LISTEN: wz_ext_link_kind_t = AppLinkKind::DatagramListen as u8;

/// What the program's `open` and `send` answer.
pub type wz_ext_link_result_t = i8;
/// Done: the link is up, or the send took `*written` bytes.
pub const WZ_EXT_LINK_OK: wz_ext_link_result_t = 0;
/// Not now: the open is under way, or the send took nothing and `writable` follows.
pub const WZ_EXT_LINK_WOULD_BLOCK: wz_ext_link_result_t = 1;
/// The link is closed.
pub const WZ_EXT_LINK_CLOSED: wz_ext_link_result_t = 2;
/// The open or the send failed.
pub const WZ_EXT_LINK_FAILED: wz_ext_link_result_t = 3;

/// What the program tells the session of a link.
pub type wz_ext_link_event_t = u8;
/// The link the session asked to open is up.
pub const WZ_EXT_LINK_EVENT_CONNECTED: wz_ext_link_event_t = 0;
/// The link is gone, or its open failed.
pub const WZ_EXT_LINK_EVENT_CLOSED: wz_ext_link_event_t = 1;
/// A link whose send would block takes bytes again.
pub const WZ_EXT_LINK_EVENT_WRITABLE: wz_ext_link_event_t = 2;

/// The program's `open(context, link, kind, locator)`; `locator` is NUL-terminated and valid for
/// the call.
pub type wz_ext_transport_open_fn = unsafe extern "C" fn(
    context: *mut c_void,
    link: wz_ext_link_t,
    kind: wz_ext_link_kind_t,
    locator: *const c_char,
) -> wz_ext_link_result_t;

/// The program's `send(context, link, data, len, written)`; `data` is valid for the call only.
pub type wz_ext_transport_send_fn = unsafe extern "C" fn(
    context: *mut c_void,
    link: wz_ext_link_t,
    data: *const u8,
    len: usize,
    written: *mut usize,
) -> wz_ext_link_result_t;

/// The program's `close(context, link)`.
pub type wz_ext_transport_close_fn =
    unsafe extern "C" fn(context: *mut c_void, link: wz_ext_link_t);

/// The program's `drained(context, link)`: `link`, which refused bytes with
/// `WZ_EXT_ERR_LINK_FULL`, has been read down and takes bytes again.
pub type wz_ext_transport_drained_fn =
    unsafe extern "C" fn(context: *mut c_void, link: wz_ext_link_t);

/// The program's `drop(context)`, run once when the transport is gone.
pub type wz_ext_transport_drop_fn = unsafe extern "C" fn(context: *mut c_void);

/// The calls the program supplies. `open`, `send` and `close` are required; `drained` and `drop`
/// may be NULL.
#[repr(C)]
pub struct wz_ext_transport_t {
    pub context: *mut c_void,
    pub open: Option<wz_ext_transport_open_fn>,
    pub send: Option<wz_ext_transport_send_fn>,
    pub close: Option<wz_ext_transport_close_fn>,
    pub drained: Option<wz_ext_transport_drained_fn>,
    pub drop: Option<wz_ext_transport_drop_fn>,
}

/// An owned transport: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_transport_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned transport: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_transport_t {
    pub(crate) handle: *mut c_void,
}

/// A moved transport (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_transport_t {
    pub(crate) _this: wz_ext_owned_transport_t,
}

impl wz_ext_owned_transport_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
        }
    }
}

/// The program's calls, as the engine's port. The program's own `drop(context)` runs when this
/// does, which is when the last reference to the transport goes.
struct ProgramPort {
    context: *mut c_void,
    open: wz_ext_transport_open_fn,
    send: wz_ext_transport_send_fn,
    close: wz_ext_transport_close_fn,
    drained: Option<wz_ext_transport_drained_fn>,
    drop: Option<wz_ext_transport_drop_fn>,
}

// SAFETY: the context and the function pointers are the program's, and the header's threading
// contract is the program's promise that its calls may be made from the session's threads.
unsafe impl Send for ProgramPort {}
// SAFETY: as above; the port holds no state of its own, so a shared reference adds nothing.
unsafe impl Sync for ProgramPort {}

impl AppPort for ProgramPort {
    fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
        let Ok(text) = std::ffi::CString::new(locator) else {
            // A locator with a NUL in it is one the program could not read.
            return ProgramOpen::Refused;
        };
        // SAFETY: the program's open, with its own context and a string valid for the call.
        let answer = unsafe { (self.open)(self.context, link, kind as u8, text.as_ptr()) };
        open_answer(answer)
    }

    fn send(&self, link: LinkHandle, bytes: &[u8]) -> ProgramSend {
        let mut written = 0usize;
        // SAFETY: the program's send, with its own context and bytes valid for the call.
        let answer = unsafe {
            (self.send)(
                self.context,
                link,
                bytes.as_ptr(),
                bytes.len(),
                &mut written,
            )
        };
        send_answer(answer, written)
    }

    fn close(&self, link: LinkHandle) {
        // SAFETY: the program's close, with its own context.
        unsafe { (self.close)(self.context, link) }
    }

    fn drained(&self, link: LinkHandle) {
        if let Some(drained) = self.drained {
            // SAFETY: the program's drained, with its own context.
            unsafe { drained(self.context, link) }
        }
    }
}

/// The lock a transport's table is held under: the port's, a host's mutex or an image's critical
/// section, whichever the build has, so the same transport serves either engine.
struct PortLock(wz_capi_port::sync::Lock<AppLinkTable>);

impl TableLock for PortLock {
    fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
        self.0.with(f);
    }
}

impl Drop for ProgramPort {
    fn drop(&mut self) {
        if let Some(drop) = self.drop {
            // SAFETY: the program's drop, once, after the last call of the others.
            unsafe { drop(self.context) }
        }
    }
}

/// What an `open` answer means. Any value but the four is a failure.
fn open_answer(answer: wz_ext_link_result_t) -> ProgramOpen {
    match answer {
        WZ_EXT_LINK_OK => ProgramOpen::Up,
        WZ_EXT_LINK_WOULD_BLOCK => ProgramOpen::Pending,
        _ => ProgramOpen::Refused,
    }
}

/// What a `send` answer means. Any value but the four is a failure; the table refuses a count
/// past what was offered.
fn send_answer(answer: wz_ext_link_result_t, written: usize) -> ProgramSend {
    match answer {
        WZ_EXT_LINK_OK => ProgramSend::Wrote(written),
        WZ_EXT_LINK_WOULD_BLOCK => ProgramSend::WouldBlock,
        WZ_EXT_LINK_CLOSED => ProgramSend::Closed,
        _ => ProgramSend::Failed,
    }
}

/// What a refused call of the program's returns.
fn refusal_code(refusal: InboundRefusal) -> ZResult {
    match refusal {
        InboundRefusal::NoSuchLink => crate::result::WZ_EXT_ERR_LINK_UNKNOWN,
        InboundRefusal::NotOpen => crate::result::WZ_EXT_ERR_LINK_NOT_OPEN,
        InboundRefusal::Closed => crate::result::WZ_EXT_ERR_LINK_CLOSED,
        InboundRefusal::WrongKind => crate::result::WZ_EXT_ERR_LINK_KIND,
        InboundRefusal::Full => crate::result::WZ_EXT_ERR_LINK_FULL,
        // A group's datagram must name the member it came from.
        InboundRefusal::NoSource => Z_ERR_NULL,
    }
}

/// The transport behind a loan, or `None` for a null loan or a gravestone.
///
/// # Safety
/// `this_` is null or a loan of a live owned transport.
unsafe fn transport_of<'a>(this_: *const wz_ext_loaned_transport_t) -> Option<&'a AppTransport> {
    if this_.is_null() || (*this_).handle.is_null() {
        return None;
    }
    Some(&*((*this_).handle as *const AppTransport))
}

/// A transport over the program's calls in `transport`, which is copied. `this_` holds the
/// gravestone on every error.
///
/// Z_OK; Z_ERR_NULL for a NULL `this_` or `transport`, or a NULL `open`, `send` or `close`.
///
/// # Safety
/// `this_` is writable; `transport` is null or readable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_new(
    this_: *mut wz_ext_owned_transport_t,
    transport: *const wz_ext_transport_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        *this_ = wz_ext_owned_transport_t::null_value();
        if transport.is_null() {
            return Z_ERR_NULL;
        }
        let calls = &*transport;
        let (Some(open), Some(send), Some(close)) = (calls.open, calls.send, calls.close) else {
            return Z_ERR_NULL;
        };
        let port = ProgramPort {
            context: calls.context,
            open,
            send,
            close,
            drained: calls.drained,
            drop: calls.drop,
        };
        let transport = Arc::new(AppTransport::new(
            Box::new(PortLock(wz_capi_port::sync::Lock::new(AppLinkTable::new()))),
            Box::new(port),
        ));
        *this_ = wz_ext_owned_transport_t {
            handle: Arc::into_raw(transport) as *mut c_void,
        };
        Z_OK
    })
}

/// The session opened from `config` uses `transport` for every link its `connect` and `listen`
/// locators name. A second call replaces the first. The config holds a reference: the program may
/// drop its own transport after this.
///
/// Z_OK; Z_ERR_NULL for a NULL config, a NULL transport or a gravestone.
///
/// # Safety
/// `config` is null or a loaned config; `transport` is null or a loan of a live transport.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_transport(
    config: *mut z_loaned_config_t,
    transport: *const wz_ext_loaned_transport_t,
) -> ZResult {
    guarded(|| {
        if config.is_null() || (*config).handle.is_null() {
            return Z_ERR_NULL;
        }
        if transport.is_null() || (*transport).handle.is_null() {
            return Z_ERR_NULL;
        }
        let raw = (*transport).handle as *const AppTransport;
        // One more reference, for the config: the program's own stays its own.
        Arc::increment_strong_count(raw);
        let shared = Arc::from_raw(raw);
        let state = &mut *((*config).handle as *mut ConfigState);
        state.transport = Some(shared);
        Z_OK
    })
}

/// The program hands in `len` bytes that arrived on `link`; `source` is the locator a datagram
/// came from, NUL-terminated, or NULL. The bytes are copied before this returns.
///
/// Z_OK; Z_ERR_NULL for a NULL transport, or NULL data with a length; Z_EINVAL for a source that
/// is not UTF-8; WZ_EXT_ERR_LINK_UNKNOWN for a link the transport does not hold;
/// WZ_EXT_ERR_LINK_NOT_OPEN before the link is up; WZ_EXT_ERR_LINK_CLOSED once it is closing or
/// closed; WZ_EXT_ERR_LINK_KIND for a listener.
///
/// # Safety
/// `transport` is null or a loan of a live transport; `data` is null or `len` readable bytes;
/// `source` is null or a C string.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_received(
    transport: *const wz_ext_loaned_transport_t,
    link: wz_ext_link_t,
    data: *const u8,
    len: usize,
    source: *const c_char,
) -> ZResult {
    guarded(|| {
        let Some(transport) = transport_of(transport) else {
            return Z_ERR_NULL;
        };
        let bytes: &[u8] = if len == 0 {
            &[]
        } else if data.is_null() {
            return Z_ERR_NULL;
        } else {
            core::slice::from_raw_parts(data, len)
        };
        let source = if source.is_null() {
            None
        } else {
            match CStr::from_ptr(source).to_str() {
                Ok(text) => Some(text),
                Err(_) => return Z_EINVAL,
            }
        };
        match transport.received(link, bytes, source) {
            Ok(()) => Z_OK,
            Err(refusal) => refusal_code(refusal),
        }
    })
}

/// The program says `event` happened to `link`.
///
/// Z_OK; Z_ERR_NULL for a NULL transport; Z_EINVAL for another event; WZ_EXT_ERR_LINK_UNKNOWN for
/// a link the transport does not hold; WZ_EXT_ERR_LINK_CLOSED for a link already closed.
///
/// # Safety
/// `transport` is null or a loan of a live transport.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_event(
    transport: *const wz_ext_loaned_transport_t,
    link: wz_ext_link_t,
    event: wz_ext_link_event_t,
) -> ZResult {
    guarded(|| {
        let Some(transport) = transport_of(transport) else {
            return Z_ERR_NULL;
        };
        let event = match event {
            WZ_EXT_LINK_EVENT_CONNECTED => ProgramEvent::Connected,
            WZ_EXT_LINK_EVENT_CLOSED => ProgramEvent::Closed,
            WZ_EXT_LINK_EVENT_WRITABLE => ProgramEvent::Writable,
            _ => return Z_EINVAL,
        };
        match transport.event(link, event) {
            Ok(()) => Z_OK,
            Err(refusal) => refusal_code(refusal),
        }
    })
}

/// The program accepted a stream on `listener`, whose remote end it names `remote` (a locator,
/// NUL-terminated); `out_link` receives the handle of the new link, which the program uses for the
/// stream from here on.
///
/// Z_OK; Z_ERR_NULL for a NULL transport, remote or out_link; Z_EINVAL for a remote that is not
/// UTF-8; WZ_EXT_ERR_LINK_UNKNOWN for a listener the transport does not hold;
/// WZ_EXT_ERR_LINK_NOT_OPEN before it is listening; WZ_EXT_ERR_LINK_CLOSED once it is closing or
/// closed; WZ_EXT_ERR_LINK_KIND for a link that is not a listener. `*out_link` is 0 on every
/// error.
///
/// # Safety
/// `transport` is null or a loan of a live transport; `remote` is null or a C string; `out_link`
/// is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_accepted(
    transport: *const wz_ext_loaned_transport_t,
    listener: wz_ext_link_t,
    remote: *const c_char,
    out_link: *mut wz_ext_link_t,
) -> ZResult {
    guarded(|| {
        if out_link.is_null() {
            return Z_ERR_NULL;
        }
        *out_link = 0;
        let Some(transport) = transport_of(transport) else {
            return Z_ERR_NULL;
        };
        if remote.is_null() {
            return Z_ERR_NULL;
        }
        let Ok(remote) = CStr::from_ptr(remote).to_str() else {
            return Z_EINVAL;
        };
        match transport.accepted(listener, remote) {
            Ok(link) => {
                *out_link = link;
                Z_OK
            }
            Err(refusal) => refusal_code(refusal),
        }
    })
}

/// The loan of a transport: a cast.
///
/// # Safety
/// `this_` is null or an owned transport.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_loan(
    this_: *const wz_ext_owned_transport_t,
) -> *const wz_ext_loaned_transport_t {
    this_.cast::<wz_ext_loaned_transport_t>()
}

/// The moved form of a transport, for `wz_ext_transport_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned transport.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_move(
    this_: *mut wz_ext_owned_transport_t,
) -> *mut wz_ext_moved_transport_t {
    this_.cast::<wz_ext_moved_transport_t>()
}

/// Release the program's reference and leave the gravestone. The configs and sessions that hold
/// the transport keep it; the program's `drop(context)` runs when the last of them goes. A second
/// drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved transport.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_transport_drop(this_: *mut wz_ext_moved_transport_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        let handle = (*this_)._this.handle;
        (*this_)._this = wz_ext_owned_transport_t::null_value();
        if !handle.is_null() {
            drop(Arc::from_raw(handle as *const AppTransport));
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_transport_null(this_: *mut wz_ext_owned_transport_t) {
    if !this_.is_null() {
        *this_ = wz_ext_owned_transport_t::null_value();
    }
}

/// Whether the slot holds a transport.
///
/// # Safety
/// `this_` is null or an owned transport.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_transport_check(
    this_: *const wz_ext_owned_transport_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}

/// Why an open over the transport `config` names would be refused before any link is opened, or
/// `None` when every locator it names is one the transport carries on this engine.
///
/// A config with neither a connect nor a listen locator would scout on the system's sockets, which
/// the transport replaces, and is refused as a capability the engine lacks. A locator no kind
/// carries (`tls/`, `serial/`, ...) is refused as an unknown scheme, and so is one of a kind this
/// build carries no link of, as the same locator over the system's sockets is: a `udp/` dial or
/// listen without the udp link on the tokio engine, a group without the multicast transport
/// (which the cooperative engine has not).
pub(crate) fn refused_open(connect: Option<&str>, listen: Option<&str>) -> Option<ZResult> {
    use wz_session_core::app_link_table::kind_for_locator;
    if connect.is_none() && listen.is_none() {
        return Some(crate::result::WZ_EXT_ERR_UNSUPPORTED);
    }
    for (locator, is_listen) in [(connect, false), (listen, true)] {
        let Some(locator) = locator else {
            continue;
        };
        let carried = match kind_for_locator(locator, is_listen) {
            None => false,
            Some(
                AppLinkKind::StreamDial | AppLinkKind::StreamListen | AppLinkKind::StreamAccepted,
            ) => true,
            Some(
                AppLinkKind::Datagram | AppLinkKind::DatagramListen | AppLinkKind::DatagramAccepted,
            ) => DATAGRAMS_CARRIED,
            Some(AppLinkKind::Group) => GROUPS_CARRIED,
        };
        if !carried {
            return Some(crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN);
        }
    }
    None
}

/// Whether this build carries datagram links, dialled and listened for: the tokio engine with its
/// udp link, or the cooperative engine, which dials `udp/` and accepts on a `udp/` listener each
/// source the program tells apart in every build.
const DATAGRAMS_CARRIED: bool = cfg!(feature = "link-udp") || !cfg!(feature = "engine-tokio");

/// Whether this build joins groups: the multicast transport, the tokio engine's.
const GROUPS_CARRIED: bool = cfg!(feature = "multicast-transport");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{WZ_EXT_ERR_UNSUPPORTED, Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN};

    #[test]
    fn the_kind_numbers_are_the_tables() {
        assert_eq!(WZ_EXT_LINK_STREAM_DIAL, 0);
        assert_eq!(WZ_EXT_LINK_STREAM_LISTEN, 1);
        assert_eq!(WZ_EXT_LINK_DATAGRAM, 2);
        assert_eq!(WZ_EXT_LINK_GROUP, 3);
        assert_eq!(WZ_EXT_LINK_DATAGRAM_LISTEN, 4);
    }

    #[test]
    fn a_full_link_and_a_sourceless_group_datagram_answer_their_codes() {
        assert_eq!(
            refusal_code(InboundRefusal::Full),
            crate::result::WZ_EXT_ERR_LINK_FULL
        );
        assert_eq!(refusal_code(InboundRefusal::NoSource), Z_ERR_NULL);
        assert_eq!(
            refusal_code(InboundRefusal::NoSuchLink),
            crate::result::WZ_EXT_ERR_LINK_UNKNOWN
        );
    }

    #[test]
    fn an_open_answer_outside_the_four_is_a_refusal() {
        assert_eq!(open_answer(WZ_EXT_LINK_OK), ProgramOpen::Up);
        assert_eq!(open_answer(WZ_EXT_LINK_WOULD_BLOCK), ProgramOpen::Pending);
        for answer in [WZ_EXT_LINK_CLOSED, WZ_EXT_LINK_FAILED, 4, -1, i8::MIN] {
            assert_eq!(open_answer(answer), ProgramOpen::Refused, "{answer}");
        }
    }

    #[test]
    fn a_send_answer_maps_onto_what_the_session_does() {
        assert_eq!(send_answer(WZ_EXT_LINK_OK, 7), ProgramSend::Wrote(7));
        assert_eq!(
            send_answer(WZ_EXT_LINK_WOULD_BLOCK, 7),
            ProgramSend::WouldBlock
        );
        assert_eq!(send_answer(WZ_EXT_LINK_CLOSED, 0), ProgramSend::Closed);
        assert_eq!(send_answer(WZ_EXT_LINK_FAILED, 0), ProgramSend::Failed);
        assert_eq!(send_answer(9, 0), ProgramSend::Failed);
    }

    #[test]
    fn an_open_over_the_transport_is_refused_for_what_it_does_not_carry() {
        assert_eq!(refused_open(Some("tcp/192.0.2.8:7447"), None), None);
        assert_eq!(refused_open(None, Some("tcp/192.0.2.8:7447")), None);
        assert_eq!(
            refused_open(Some("tcp/192.0.2.8:7447"), Some("tcp/192.0.2.9:7447")),
            None
        );
        assert_eq!(refused_open(None, None), Some(WZ_EXT_ERR_UNSUPPORTED));
        assert_eq!(
            refused_open(Some("tls/192.0.2.8:7447"), None),
            Some(Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN)
        );
        let refused_unless =
            |carried: bool| (!carried).then_some(Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN);
        assert_eq!(
            refused_open(None, Some("udp/192.0.2.8:7447")),
            refused_unless(DATAGRAMS_CARRIED)
        );
        assert_eq!(
            refused_open(Some("udp/192.0.2.8:7447"), None),
            refused_unless(DATAGRAMS_CARRIED)
        );
        assert_eq!(
            refused_open(None, Some("udp/239.4.5.6:7447#iface=lan7")),
            refused_unless(GROUPS_CARRIED)
        );
    }

    /// The cooperative engine dials `udp/` and listens on it over the program's transport in
    /// every build, so neither is refused before the open.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn the_cooperative_engine_carries_a_udp_dial_and_a_udp_listen() {
        assert_eq!(refused_open(Some("udp/192.0.2.8:7447"), None), None);
        assert_eq!(refused_open(None, Some("udp/192.0.2.8:7447")), None);
        assert_eq!(
            refused_open(Some("udp/192.0.2.8:7447"), Some("udp/192.0.2.9:7447")),
            None
        );
    }
}
