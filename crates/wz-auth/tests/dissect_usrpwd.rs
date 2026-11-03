// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The dissector reads the usrpwd body THIS TREE'S OWN method writes, in the frame the live
//! initiator sends.
//!
//! `wz-session-core`'s dissector names the usrpwd sub-extension of an Open's auth chain and walks
//! its `{user, hmac}` body. Its own tests lay that body out by hand; this one has the producer
//! write it. The usrpwd method runs a whole handshake against a responder through two
//! `AuthDispatch`es, its OpenSyn contribution is muxed into the auth extension, and the core's
//! own `encode_open` writes the OpenSyn around it. A divergence between the method's encoder and
//! the dissector's reading reds here rather than on a capture. The test lives in this crate
//! because the core never names the method (`scripts/lib/layer_direction_gate.py`).

use wz_auth::usrpwd::UsrPwdMethod;
use wz_codecs::whatami::WhatAmI;
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::dissect::{dissect_transport_message, Field, FieldValue};
use wz_session_core::handshake_encode::encode_open;
use wz_session_core::session_init_params::{
    cookie_bytes, zid_bytes, KeepAliveConf, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::signing_key::SigningKey;
use wz_session_core::transport_profile::ExtEntryOwned;

fn params() -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[0x11; 16]),
        seq_num_res: 2,
        req_id_res: 1,
        batch_size: 1472,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::default(),
        initial_sn: 77,
        cookie: cookie_bytes(&[]),
        tx_queue: TxQueueConf::default(),
        link_rx: LinkRxConf::default(),
        cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect("key"),
    }
}

fn exts(ext: Option<ExtEntryOwned>) -> Vec<ExtEntryOwned> {
    ext.into_iter().collect()
}

/// The sub-extension of `auth` the dissector named `method`.
fn sub_ext<'a>(auth: &'a Field, method: &str) -> &'a Field {
    let FieldValue::Nested(children) = &auth.value else {
        panic!("the auth chain is a group: {auth:?}");
    };
    children
        .iter()
        .find(|f| {
            f.name == "ext"
                && matches!(
                    f.find("ext_name").map(|n| &n.value),
                    Some(FieldValue::Label(l)) if l.as_ref() == method,
                )
        })
        .unwrap_or_else(|| panic!("the {method} sub-ext must be named"))
}

fn bytes_of(body: &Field, name: &str) -> Vec<u8> {
    match body.find(name).map(|f| &f.value) {
        Some(FieldValue::Bytes(v)) => v.clone(),
        other => panic!("{name} is not bytes: {other:?}"),
    }
}

#[test]
fn the_usrpwd_body_this_tree_writes_is_the_one_its_dissector_reads() {
    let mut open = AuthDispatch::new(vec![Box::new(UsrPwdMethod::initiator(
        b"bob".to_vec(),
        b"hunter2".to_vec(),
    )) as _]);
    let mut accept = AuthDispatch::new(vec![Box::new(UsrPwdMethod::responder(
        vec![(b"bob".to_vec(), b"hunter2".to_vec())],
        0x0102_0304_0506_0708,
    )) as _]);
    let init_syn = open.open_init_syn().expect("InitSyn");
    accept
        .accept_recv_init_syn(&exts(init_syn))
        .expect("the responder takes the offer");
    let init_ack = accept.accept_init_ack().expect("InitAck");
    open.open_recv_init_ack(&exts(init_ack))
        .expect("the initiator takes the challenge");
    let open_syn = open
        .open_open_syn()
        .expect("OpenSyn")
        .expect("usrpwd contributes to the OpenSyn");

    // The control: the responder accepts this very extension, so what the dissector reads
    // below is a body that authenticates, not one the producer would never send.
    let who = accept
        .accept_recv_open_syn(std::slice::from_ref(&open_syn))
        .expect("the responder verifies the OpenSyn");
    assert_eq!(who.map(|id| id.0), Some(b"bob".to_vec()));

    let frame = encode_open(&params(), false, Some(&[0xC0, 0x0C]), &[open_syn])
        .expect("the OpenSyn encodes");
    let walked = dissect_transport_message(&frame, 0).expect("the dissector reads the OpenSyn");
    assert_eq!(walked.span.end, frame.len(), "the walk tiles the frame");

    let auth = walked
        .find("extensions")
        .and_then(|e| e.find("auth"))
        .expect("the auth extension is walked");
    let entry = sub_ext(auth, "usrpwd");
    assert!(
        entry.find("value").is_none(),
        "a walked body is not also shown as opaque bytes"
    );
    let body = entry.find("usrpwd").expect("the usrpwd body is walked");
    assert_eq!(
        bytes_of(body, "user"),
        b"bob".to_vec(),
        "the producer's own user reaches the reader"
    );
    assert_eq!(
        bytes_of(body, "hmac").len(),
        32,
        "HMAC-SHA3-256 is 32 bytes, so the walker found the SECOND record rather than the tail \
         of the first"
    );
}
