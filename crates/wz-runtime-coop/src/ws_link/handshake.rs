// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The opening handshake of a WebSocket link, written once for the links of both profiles: the
//! heap profile's dial and listener (`links`) and the slot profile's stack and acceptor (`slot`).
//! What each step reads is read into the receive buffer of the link it makes, so what the peer sent
//! behind its head is the link's first bytes.

use core::net::SocketAddr;

use wz_session_core::ws_link::{
    client_key, read_request, read_response, write_request, write_response, MaskKeys, RequestRead,
    UpgradeRead, KEY_LEN, MASK_SEED_LEN,
};

use super::WsSource;
use crate::link_storage::RxStore;
use crate::session_drive::LinkOpenError;
use crate::stream_link::StreamSocket;

/// The longest an opening handshake takes, in microseconds: the connect timeout of a zenoh-pico
/// session, which a waiting open of a serial line is held to as well.
pub(crate) const OPEN_WAIT_US: u64 = 10_000_000;

/// The room an opening request or answer is written in: the longest, a request to a scoped IPv6
/// end, is some two hundred bytes.
const HEAD_ROOM: usize = 256;

/// The bytes of the nonce a client's key is the base64 of.
const KEY_NONCE_LEN: usize = 16;

/// A client's key and the generator of its mask keys, drawn from `source`'s entropy: a source
/// that has none refuses the dial as one worth trying later.
pub(crate) fn client_keys<W: WsSource + ?Sized>(
    source: &W,
) -> Result<([u8; KEY_LEN], MaskKeys), LinkOpenError> {
    let mut seed = [0u8; KEY_NONCE_LEN + MASK_SEED_LEN];
    source
        .fill_entropy(&mut seed)
        .map_err(|_| LinkOpenError::Refused)?;
    let (nonce, mask_seed) = seed.split_at(KEY_NONCE_LEN);
    let (Ok(nonce), Ok(mask_seed)) = (
        <&[u8; KEY_NONCE_LEN]>::try_from(nonce),
        <&[u8; MASK_SEED_LEN]>::try_from(mask_seed),
    ) else {
        return Err(LinkOpenError::Refused);
    };
    Ok((client_key(nonce), MaskKeys::seeded(mask_seed)))
}

/// Write the client's opening request to `at` with `key` on `stream`: an end whose request does
/// not fit the room is one this link cannot name, and a stream that fails the write has refused it.
pub(crate) fn send_request<P: StreamSocket>(
    stream: &P,
    at: SocketAddr,
    key: &[u8; KEY_LEN],
) -> Result<(), LinkOpenError> {
    let mut request = [0u8; HEAD_ROOM];
    let len = write_request(&mut request, at, key).ok_or(LinkOpenError::Unsupported)?;
    stream
        .write_all(request.get(..len).unwrap_or_default())
        .map_err(|_| LinkOpenError::Refused)
}

/// Read the server's answer to the request made with `key` into `rx`, behind the `filled` bytes
/// read before, without waiting: once it upgraded the connection, how many bytes followed its head
/// (moved to the front of `rx`); `None` while it has not all arrived.
pub(crate) fn read_answer<P: StreamSocket, B: RxStore>(
    stream: &P,
    rx: &mut B,
    filled: &mut usize,
    key: &[u8; KEY_LEN],
) -> Option<Result<usize, LinkOpenError>> {
    read_handshake(stream, rx, filled, |held| match read_response(held, key) {
        UpgradeRead::Partial => None,
        UpgradeRead::Upgraded { head_len } => Some(Ok((head_len, ()))),
        UpgradeRead::Refused => Some(Err(())),
    })
    .map(|made| made.map(|((), held)| held))
}

/// Read a client's opening request into `rx`, behind the `filled` bytes read before, without
/// waiting, and answer it on `stream` once it is whole: how many bytes followed its head (moved to
/// the front of `rx`); `None` while it has not all arrived.
pub(crate) fn answer_request<P: StreamSocket, B: RxStore>(
    stream: &P,
    rx: &mut B,
    filled: &mut usize,
) -> Option<Result<usize, LinkOpenError>> {
    let read = read_handshake(stream, rx, filled, |held| match read_request(held) {
        RequestRead::Partial => None,
        RequestRead::Upgrade { head_len, accept } => Some(Ok((head_len, accept))),
        RequestRead::Refused => Some(Err(())),
    })?;
    Some(read.and_then(|(accept, held)| {
        let mut answer = [0u8; HEAD_ROOM];
        let len = write_response(&mut answer, &accept).ok_or(LinkOpenError::Unsupported)?;
        stream
            .write_all(answer.get(..len).unwrap_or_default())
            .map_err(|_| LinkOpenError::Refused)?;
        Ok(held)
    }))
}

/// Read what `stream` has queued behind the `filled` bytes at the front of `rx` until `head`
/// finds the head of a handshake whole in them: the bytes read so far while it has not, and once
/// it has, what `head` made of it with what followed the head moved to the front of the buffer,
/// and how many bytes that is. A stream that ended or failed, a buffer the head does not fit, or
/// a head `head` refuses is `Err`.
fn read_handshake<P: StreamSocket, B: RxStore, A>(
    stream: &P,
    rx: &mut B,
    filled: &mut usize,
    head: impl Fn(&[u8]) -> Option<Result<(usize, A), ()>>,
) -> Option<Result<(A, usize), LinkOpenError>> {
    let Some(bytes) = rx.bytes() else {
        return Some(Err(LinkOpenError::Exhausted));
    };
    loop {
        match head(bytes.get(..*filled).unwrap_or_default()) {
            Some(Ok((head_len, answer))) => {
                bytes.copy_within(head_len..*filled, 0);
                return Some(Ok((answer, filled.saturating_sub(head_len))));
            }
            Some(Err(())) => return Some(Err(LinkOpenError::Refused)),
            None => {}
        }
        let room = bytes.get_mut(*filled..).unwrap_or_default();
        if room.is_empty() {
            return Some(Err(LinkOpenError::Refused));
        }
        match stream.try_read(room) {
            Ok(Some(0)) | Err(_) => return Some(Err(LinkOpenError::Refused)),
            Ok(None) => return None,
            Ok(Some(read)) => *filled = filled.saturating_add(read),
        }
    }
}
