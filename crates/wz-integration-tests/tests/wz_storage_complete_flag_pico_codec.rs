// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y370 (pico cross-impl leg) §5.24 storage — the `storage-mgr-complete-flag`
//! wz->pico witness: a wz `StorageService` declared with `StorageConfig.complete`
//! = true / false emits a DeclareQueryable whose `QueryableInfo` complete bit is
//! DECODED by pico's real C `_z_declaration_decode`, which AGREES with the
//! configured value. The foreign C impl reading the wire bit is what makes this a
//! cross-impl proof (not a wz-internal round-trip).
//!
//! ## What binds the claim (`storage-mgr-complete-flag`, NOT `declare-queryable`)
//!
//! `declare-queryable` (the wire DeclareQueryable envelope) is already proven
//! cross-impl; what is unique to `storage-mgr-complete-flag` is the config-driven
//! COMPLETE bit — `StorageService::declare_with_backend` feeds
//! `storage_queryable_complete(config.complete)` to
//! `QueryableOptions::with_complete` (storage_service.rs:211), and that gate
//! (storage_service.rs:108-116) honors `config.complete` ONLY under the
//! `storage-mgr-complete-flag` feature (with it off the queryable is always
//! complete = the pre-y59 behavior). So the load-bearing signal is that BOTH
//! config values survive to the wire: `complete = true` yields a wire complete
//! bit pico reads as `true`, and `complete = false` yields a bit pico reads as
//! `false` (the ext is omitted on the zenoh-faithful default). A pure
//! DeclareQueryable codec-parity test would be insensitive to the storage gate
//! (neutering `storage_queryable_complete` would not fail it); driving the gate
//! and reading BOTH directions off the wire is what binds to this atom's code.
//!
//! ## The observable (pico's C decoder agrees on the complete bit)
//!
//! The test drives an in-process wz `StorageService` over a recording-driver
//! session (`establish_capability_pair` -> Established, no socket), captures the
//! DeclareQueryable the declare emits, decodes it down to the `DeclQueryable`,
//! re-serializes that one declaration, and hands the bytes to pico's real C
//! `_z_declaration_decode`. pico's
//! `_z_decl_queryable_t._ext_queryable_info._complete` is asserted to equal the
//! configured value. RED (binds to the storage gate): neuter
//! `storage_queryable_complete` so it ignores `configured` (e.g. always return
//! `true`) and rebuild -> the `complete = false` case emits a complete bit pico
//! decodes as `true`, so the assertion fails while the `complete = true` case
//! still passes; the proof binds to the config->wire threading, not to a flag.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! Everything is synchronous and transport-free: `establish_capability_pair`
//! drives a deterministic in-memory handshake to Established, the declare's wire
//! emission is a synchronous `send_blocking` captured in the driver's `sends`
//! log, and pico's decode is a pure function of those captured bytes. There is no
//! socket, no spawned binary, no timing, and no deadline. Links the vendored
//! zenoh-pico C library (`crates/zenoh-pico-sys`) like the `layer3_*` codec
//! tests, so it runs in Layer C1 on every push (NOT `#[ignore]`d).

use std::sync::Arc;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::{
    parse_frame_payload, parse_inbound, InboundFrame, NetworkMessage,
};
use wz_runtime_tokio::storage_service::StorageService;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::establish_capability_pair;
use wz_session_core::storage_config::StorageConfig;

use zenoh_pico_sys::{
    _z_declaration_decode, _z_declaration_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_wbuf_write_bytes, _z_zbuf_clear,
};

/// Tag ordinal for `_Z_DECL_QUERYABLE` in pico's `_z_declaration_t._tag`
/// anonymous enum (KEXPR=0, UNDECL_KEXPR=1, DECL_SUBSCRIBER=2,
/// UNDECL_SUBSCRIBER=3, DECL_QUERYABLE=4). Matched by integer literal so this
/// test stays robust to bindgen's exact naming for the anonymous enum — the same
/// approach `layer3_declare.rs` takes for `_Z_DECL_FINAL` (= 8).
const Z_DECL_QUERYABLE_TAG: u32 = 4;

/// The keyexpr the wz `StorageService` captures + answers on. `**` so the
/// declared queryable carries a literal suffix (a non-trivial commons for pico's
/// decoder to parse before it reaches the QueryableInfo ext).
const STORAGE_KEYEXPR: &str = "complete-flag-probe/**";

/// Feed one wz-emitted DeclareQueryable *declaration* (header + id + keyexpr +
/// ext chain) to pico's real C `_z_declaration_decode` and return the complete
/// bit it decoded. The foreign-agreement witness.
fn pico_decoded_complete(declaration_bytes: &[u8]) -> bool {
    // SAFETY: the standard wbuf-fill -> zbuf -> decode path (mirrors
    // layer3_declare.rs's wbuf/zbuf usage). `declaration_bytes` is exactly one
    // wz-emitted DeclareQueryable declaration; pico parses the commons
    // (id/keyexpr) then the non-mandatory QueryableInfo z64 ext, filling
    // `_ext_queryable_info`. The mapping arg (0) is only consulted for the
    // keyexpr, which we do not inspect. The decoded keyexpr allocates a small
    // suffix string that is left to the one-shot test process (no clear helper
    // is allowlisted); zbuf/wbuf are cleared.
    unsafe {
        let mut wbf = _z_wbuf_make(512, false);
        let w = _z_wbuf_write_bytes(
            &mut wbf,
            declaration_bytes.as_ptr(),
            0,
            declaration_bytes.len(),
        );
        assert_eq!(w, 0, "wbuf write of wz declaration bytes failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);

        let mut decl = _z_declaration_t::default();
        let ret = _z_declaration_decode(&mut decl, &mut zbf, 0);
        assert_eq!(
            ret, 0,
            "pico _z_declaration_decode rejected wz's DeclareQueryable bytes: {declaration_bytes:02x?}"
        );
        assert_eq!(
            decl._tag, Z_DECL_QUERYABLE_TAG,
            "decoded declaration is not a DeclareQueryable (tag {})",
            decl._tag
        );
        let complete = decl._body._decl_queryable._ext_queryable_info._complete;

        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        complete
    }
}

/// Drive an in-process wz `StorageService` with `config_complete`, capture the
/// DeclareQueryable it emits, and return the complete bit pico's C decoder reads
/// off those wire bytes.
async fn wire_complete_seen_by_pico(config_complete: bool) -> bool {
    // Established wz session over recording drivers (deterministic, no socket).
    let pair = establish_capability_pair(false, false, |_| {}).await;
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(pair.resp_actions.clone(), observer, clock);

    // Snapshot the sends BEFORE the declare so we isolate the frames the storage
    // declare adds (the handshake frames precede them).
    let before = pair.resp_driver.snapshot().sends.len();

    let mut config = StorageConfig::new("probe", STORAGE_KEYEXPR, "mem");
    config.complete = config_complete;
    let _storage = StorageService::declare(&session, &config, vec![0x01])
        .expect("wz storage declares against the recording-driver session");

    // Scan the frames emitted by the declare for the (single) DeclareQueryable.
    // The declare emits a capture DeclareSubscriber and an answering
    // DeclareQueryable; only the queryable body carries QueryableInfo.
    let sends = pair.resp_driver.snapshot().sends;
    let mut found: Option<Vec<u8>> = None;
    for (frame, _reliability) in &sends[before..] {
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("emitted frame parses as an inbound transport frame")
        else {
            continue;
        };
        let Ok(messages) = parse_frame_payload(&payload) else {
            continue;
        };
        for msg in messages {
            if let NetworkMessage::Declare(decl) = msg {
                if let wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclQueryable(dq) =
                    &decl.body
                {
                    let declaration = dq
                        .try_as_borrowed()
                        .expect("<=N exts by construction")
                        .encode_to_vec();
                    assert!(
                        found.is_none(),
                        "expected exactly one DeclareQueryable from the storage declare"
                    );
                    found = Some(declaration);
                }
            }
        }
    }

    let declaration = found
        .expect("the storage declare emitted a DeclareQueryable frame over the recording driver");
    pico_decoded_complete(&declaration)
}

/// A wz `StorageService`'s config-driven COMPLETE bit survives to the wire in
/// BOTH directions, as read back by pico's real C `_z_declaration_decode` — the
/// §5.24 `storage-mgr-complete-flag` wz->pico cross-impl witness. `complete =
/// true` -> pico decodes `true` (the QueryableInfo ext is emitted); `complete =
/// false` -> pico decodes `false` (the ext is omitted on the zenoh-faithful
/// default). Binds to the `storage_queryable_complete` config->wire gate: the
/// false case is what fails if the gate stops honoring `config.complete`.
// wz-proves: storage-mgr-complete-flag wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_storage_complete_flag_is_decoded_by_pico_both_ways() {
    assert!(
        wire_complete_seen_by_pico(true).await,
        "config complete=true must reach the wire as a complete QueryableInfo bit pico decodes as true"
    );
    assert!(
        !wire_complete_seen_by_pico(false).await,
        "config complete=false must reach the wire as an incomplete queryable pico decodes as false \
         (RED if storage_queryable_complete stops honoring config.complete)"
    );
}
