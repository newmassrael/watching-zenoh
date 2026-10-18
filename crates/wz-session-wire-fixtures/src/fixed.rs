// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The crafted frames of the crate root, written into a buffer the caller's stack
//! holds, with no allocator (fixed-memory step S9c).
//!
//! The `Vec`-returning forms at the crate root are behind the `alloc` feature, and an
//! image on the fixed-memory profile drives its reactive peer with these. They are
//! the SAME bytes as the `Vec` forms of the frames the acceptor e2e sends
//! (`craft_initsyn_wire`, `craft_opensyn_wire`, `craft_frame_wire` and
//! `craft_fragment_wire`, which exist with the `alloc` feature), held equal by
//! `tests::the_fixed_forms_are_the_vec_forms` (the `Vec` forms stay as they were:
//! other crates feed them payloads longer than a stack buffer here holds), so a spec
//! change touches both and the test names the one left behind.

use crate::{
    FIXTURE_PEER_ZID, FLAG_T_FRAGMENT_M, FLAG_T_FRAGMENT_R, FLAG_T_FRAME_R, FLAG_T_INIT_S,
    T_MID_FRAGMENT, T_MID_FRAME, T_MID_INIT, T_MID_OPEN,
};

/// The bytes of one crafted frame, in an array of `N` that the frame must fit: a
/// fixture asserts it fits, as it asserts a single-byte length, rather than cut a
/// frame short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Wire<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn push(&mut self, byte: u8) {
        assert!(self.len < N, "fixture: the frame does not fit its buffer");
        self.bytes[self.len] = byte;
        self.len += 1;
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        assert!(
            self.len + bytes.len() <= N,
            "fixture: the frame does not fit its buffer"
        );
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// The frame's bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The room of [`opensyn`]: the header, the two VLEs, the length byte and a cookie of
/// up to 127 bytes (a single-byte VLE length).
pub const OPENSYN_BYTES: usize = 4 + 127;
/// The room of [`initsyn`].
pub const INITSYN_BYTES: usize = 10;
/// The room of [`frame`].
pub const FRAME_BYTES: usize = 2;
/// The room of [`fragment`]: the header, the sequence number and a payload of up to 62
/// bytes, which is as much as the e2e's chains carry.
pub const FRAGMENT_BYTES: usize = 64;

/// Minimal `InitSyn` (parent flag `FLAG_T_INIT_S`, no `_A` so no cookie): version,
/// cbyte (whatami=Peer wire 0x01 | (zid_len-1)<<4), 4-byte `FIXTURE_PEER_ZID`,
/// sn_res, batch_size LE u16.
pub fn initsyn() -> Wire<INITSYN_BYTES> {
    let mut wire = Wire::new();
    wire.push(FLAG_T_INIT_S | T_MID_INIT);
    wire.push(0x05); // version
    wire.push(0x31); // cbyte: whatami=Peer wire(0x01), zid_len=4 (high nibble = 3)
    wire.extend_from_slice(&FIXTURE_PEER_ZID);
    wire.extend_from_slice(&[
        0x00, // sn_res (seq=0, req=0)
        0x00, 0x00, // batch_size LE u16 = 0
    ]);
    wire
}

/// `OpenSyn` echoing `cookie` (parent flags 0x00 so the cookie carrier is present
/// and the lease is in ms): lease VLE=0, initial_sn VLE=0, cookie_len VLE, cookie
/// bytes.
pub fn opensyn(cookie: &[u8]) -> Wire<OPENSYN_BYTES> {
    assert!(
        cookie.len() < 0x80,
        "fixture: single-byte VLE cookie_len only"
    );
    let mut wire = Wire::new();
    wire.push(T_MID_OPEN);
    wire.push(0x00); // lease VLE = 0
    wire.push(0x00); // initial_sn VLE = 0
    wire.push(cookie.len() as u8); // VLE cookie_len (< 0x80 single byte)
    wire.extend_from_slice(cookie);
    wire
}

/// Application `Frame` with the `R` (reliable) flag set per `reliable`, a
/// single-byte-VLE `sn`, and an empty payload (decodes to a `FramePayload` with an
/// empty NetworkMessage batch).
pub fn frame(sn: u64, reliable: bool) -> Wire<FRAME_BYTES> {
    assert!(sn < 0x80, "fixture: single-byte VLE sn only");
    let mut wire = Wire::new();
    wire.push(if reliable {
        FLAG_T_FRAME_R | T_MID_FRAME
    } else {
        T_MID_FRAME
    });
    wire.push(sn as u8);
    wire
}

/// Transport `Fragment` (`T_MID_FRAGMENT`): header byte `(R?|M?|T_MID_FRAGMENT)`, a
/// single-byte-VLE `sn`, then the tail `payload`. The body mirrors `T_MID_FRAME`
/// (VLE sn + tail); no Z (ext) bit. A chain's non-final fragments set `more`.
pub fn fragment(reliable: bool, more: bool, sn: u64, payload: &[u8]) -> Wire<FRAGMENT_BYTES> {
    assert!(sn < 0x80, "fixture: single-byte VLE sn only");
    let mut flags = 0u8;
    if reliable {
        flags |= FLAG_T_FRAGMENT_R;
    }
    if more {
        flags |= FLAG_T_FRAGMENT_M;
    }
    let mut wire = Wire::new();
    wire.push(flags | T_MID_FRAGMENT);
    wire.push(sn as u8);
    wire.extend_from_slice(payload);
    wire
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{craft_fragment_wire, craft_frame_wire, craft_initsyn_wire, craft_opensyn_wire};

    /// The stack-buffer forms are the `Vec` forms: the same bytes for every shape the
    /// acceptor e2e sends (both fragment flag combinations, a cookie of every width up
    /// to the single-byte VLE bound, both frame channels).
    #[test]
    fn the_fixed_forms_are_the_vec_forms() {
        assert_eq!(initsyn().as_slice(), craft_initsyn_wire().as_slice());
        for len in [0usize, 1, 16, 127] {
            let cookie: alloc::vec::Vec<u8> = (0..len as u8).collect();
            assert_eq!(
                opensyn(&cookie).as_slice(),
                craft_opensyn_wire(&cookie).as_slice(),
                "cookie of {len}"
            );
        }
        for (sn, reliable) in [(0u64, true), (7, true), (127, false)] {
            assert_eq!(
                frame(sn, reliable).as_slice(),
                craft_frame_wire(sn, reliable).as_slice()
            );
        }
        for (reliable, more) in [(true, true), (true, false), (false, true), (false, false)] {
            for payload in [&[][..], &[0x01][..], &[0x02, 0x03, 0x04][..]] {
                assert_eq!(
                    fragment(reliable, more, 11, payload).as_slice(),
                    craft_fragment_wire(reliable, more, 11, payload).as_slice()
                );
            }
        }
    }

    /// A frame that does not fit its buffer is refused where it is built, never cut.
    #[test]
    #[should_panic(expected = "does not fit")]
    fn a_frame_past_its_buffer_is_refused() {
        let _ = fragment(true, false, 1, &[0u8; FRAGMENT_BYTES]);
    }
}
