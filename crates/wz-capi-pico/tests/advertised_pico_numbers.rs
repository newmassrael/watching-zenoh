// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session of this ABI advertises the numbers of zenoh-pico's value build switches, as the
//! build states them, and not zenoh's: its InitSyn carries pico's `BATCH_UNICAST_SIZE`
//! (`vendor/zenoh-pico/src/protocol/definitions/transport.c` @
//! `msg._body._init._batch_size = Z_BATCH_UNICAST_SIZE;`), 2048 by default, where zenoh's is
//! 65535.
//!
//! The peer is a bare TCP listener: it reads the first frame the session sends and closes, so
//! what is compared is the bytes on the wire and not a value the session reports about itself.
//! The InitSyn layout is zenoh's: a header byte `|Z|S|A| INIT`, the version, a byte whose high
//! nibble is the zid's length less one, the zid, and, when `S` is set, the resolutions and the
//! batch size as two little-endian bytes. pico sets `S` whenever its numbers differ from the
//! protocol defaults, and so must this.

use std::ffi::CString;
use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc::channel;
use std::time::Duration;

use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_move, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_OK,
};
use wz_session_core::caps::PICO_UNICAST_BATCH_BYTES;

/// zenoh's INIT message id, the low five bits of the header.
const MID_INIT: u8 = 0x01;
/// The header's `A` flag: an InitAck, not an InitSyn.
const FLAG_ACK: u8 = 0x20;
/// The header's `S` flag: the resolutions and the batch size follow the zid.
const FLAG_SIZE: u8 = 0x40;
/// The batch size an InitSyn without `S` stands for: zenoh's protocol default.
const PROTOCOL_DEFAULT_BATCH: u16 = 65535;

/// The batch size the first InitSyn on `stream` advertises: the frame after the stream link's
/// two-byte length.
fn advertised_batch(stream: &mut std::net::TcpStream) -> u16 {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).expect("the frame's length");
    let mut frame = vec![0u8; u16::from_le_bytes(len) as usize];
    stream.read_exact(&mut frame).expect("the frame");
    let header = frame[0];
    assert_eq!(
        header & 0x1F,
        MID_INIT,
        "the session's first message is an INIT: {frame:02x?}"
    );
    assert_eq!(
        header & FLAG_ACK,
        0,
        "it is an InitSyn, not an InitAck: {frame:02x?}"
    );
    if header & FLAG_SIZE == 0 {
        return PROTOCOL_DEFAULT_BATCH;
    }
    let zid_len = ((frame[2] >> 4) as usize) + 1;
    let at = 3 + zid_len + 1;
    u16::from_le_bytes([frame[at], frame[at + 1]])
}

/// A build that states no number states pico's own default (`vendor/zenoh-pico/CMakeLists.txt` @
/// `set(BATCH_UNICAST_SIZE 2048`). Only a default build runs it: one that states another number
/// is the subject of the test below, not a failure of this one.
#[test]
fn a_build_that_states_no_number_states_picos_default() {
    if option_env!("WZ_LIMIT_PICO_UNICAST_BATCH_BYTES").is_some() {
        return;
    }
    assert_eq!(PICO_UNICAST_BATCH_BYTES, 2048);
}

#[test]
fn the_init_syn_advertises_the_unicast_batch_size_the_build_states() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().expect("its port").port();

    let (done_tx, done_rx) = channel();
    let opener = std::thread::spawn(move || unsafe {
        let mut config: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut config), Z_OK);
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut config),
                Z_CONFIG_CONNECT_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        // The peer closes after the InitSyn, so the open fails: what it sent is the subject.
        if z_open(&mut session, z_config_move(&mut config), std::ptr::null()) == Z_OK {
            z_session_drop(z_session_move(&mut session));
        }
        let _ = done_tx.send(());
    });

    let (mut stream, _) = listener.accept().expect("the session dials");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");
    let batch = advertised_batch(&mut stream);
    drop(stream);
    drop(listener);
    done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the open returns once its peer is gone");
    opener.join().expect("the opener thread");

    assert_eq!(
        batch, PICO_UNICAST_BATCH_BYTES as u16,
        "the InitSyn advertises the batch size the build states for pico's BATCH_UNICAST_SIZE"
    );
}
