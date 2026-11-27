

// SCE Forge: Auto-generated codec test-vector sidecar (RFC §synth-5-B)
// Companion to frame.rs — do not edit; regenerate from the source SCXML.

#[test]
fn test_vector_frame_l47() {
    let actual = Frame {
        sn: 0x0u64,
        payload: (b"").into(),
    };
    let encoded = actual.encode_to_vec();
    let expected: &[u8] = &[0x00u8];
    assert_eq!(
        encoded.as_slice(), expected,
        "<sce:test-vector> at SCXML L47: encode produced {:?}, expected {:?}",
        encoded, expected
    );
    let mut cursor = SceCursor::new(expected);
    let decoded = Frame::decode(&mut cursor)
        .expect("<sce:test-vector> at SCXML L47: decode failed");
    assert_eq!(
        cursor.remaining(), 0,
        "<sce:test-vector> at SCXML L47: decode left {} bytes unconsumed",
        cursor.remaining()
    );
    assert_eq!(
        decoded.sn, 0x0u64,
        "<sce:test-vector> at SCXML L47: field `sn` mismatch"
    );
    assert_eq!(
        decoded.payload, b"",
        "<sce:test-vector> at SCXML L47: field `payload` mismatch"
    );
    // Owned-projection round-trip (acceptance #2): deep-copy the borrowed
    // decode into its no-alloc owned mirror and assert every field still
    // equals the oracle. An owned bytes or text field held within its bound
    // lends its value with the bounds, which compares against the `&[u8]` /
    // `&str` literal (docs/adr/0077 §3). `try_into_owned` is fallible (the bounded
    // copy re-checks the decode bound); the decode above already proved the
    // value fits, so the projection cannot fail here.
    let owned = Frame::decode(&mut SceCursor::new(expected))
        .expect("<sce:test-vector> at SCXML L47: decode for into_owned failed")
        .try_into_owned()
        .expect("<sce:test-vector> at SCXML L47: try_into_owned exceeded a bounded field");
    assert_eq!(
        owned.sn, 0x0u64,
        "<sce:test-vector> at SCXML L47: into_owned field `sn` mismatch"
    );
    assert_eq!(
        owned.payload.as_bytes(), b"",
        "<sce:test-vector> at SCXML L47: into_owned field `payload` mismatch"
    );
    // Owned→borrowed projection round-trip (acceptance #2): re-borrow the
    // owned mirror back into the zero-copy view and assert it re-encodes to
    // the exact oracle bytes — closing the borrowed→owned→borrowed loop so
    // an owned value reaches the borrowed-only `encode`. Every sidecar-
    // eligible codec is scalar / bytes / string (no bounded list reaches
    // this gate), so the projection is infallible.
    assert_eq!(
        owned.as_borrowed().encode_to_vec().as_slice(), expected,
        "<sce:test-vector> at SCXML L47: as_borrowed re-encode mismatch"
    );
}
#[test]
fn test_vector_frame_l51() {
    let actual = Frame {
        sn: 0x1u64,
        payload: (b"\xca\xfe").into(),
    };
    let encoded = actual.encode_to_vec();
    let expected: &[u8] = &[0x01u8, 0xcau8, 0xfeu8];
    assert_eq!(
        encoded.as_slice(), expected,
        "<sce:test-vector> at SCXML L51: encode produced {:?}, expected {:?}",
        encoded, expected
    );
    let mut cursor = SceCursor::new(expected);
    let decoded = Frame::decode(&mut cursor)
        .expect("<sce:test-vector> at SCXML L51: decode failed");
    assert_eq!(
        cursor.remaining(), 0,
        "<sce:test-vector> at SCXML L51: decode left {} bytes unconsumed",
        cursor.remaining()
    );
    assert_eq!(
        decoded.sn, 0x1u64,
        "<sce:test-vector> at SCXML L51: field `sn` mismatch"
    );
    assert_eq!(
        decoded.payload, b"\xca\xfe",
        "<sce:test-vector> at SCXML L51: field `payload` mismatch"
    );
    // Owned-projection round-trip (acceptance #2): deep-copy the borrowed
    // decode into its no-alloc owned mirror and assert every field still
    // equals the oracle. An owned bytes or text field held within its bound
    // lends its value with the bounds, which compares against the `&[u8]` /
    // `&str` literal (docs/adr/0077 §3). `try_into_owned` is fallible (the bounded
    // copy re-checks the decode bound); the decode above already proved the
    // value fits, so the projection cannot fail here.
    let owned = Frame::decode(&mut SceCursor::new(expected))
        .expect("<sce:test-vector> at SCXML L51: decode for into_owned failed")
        .try_into_owned()
        .expect("<sce:test-vector> at SCXML L51: try_into_owned exceeded a bounded field");
    assert_eq!(
        owned.sn, 0x1u64,
        "<sce:test-vector> at SCXML L51: into_owned field `sn` mismatch"
    );
    assert_eq!(
        owned.payload.as_bytes(), b"\xca\xfe",
        "<sce:test-vector> at SCXML L51: into_owned field `payload` mismatch"
    );
    // Owned→borrowed projection round-trip (acceptance #2): re-borrow the
    // owned mirror back into the zero-copy view and assert it re-encodes to
    // the exact oracle bytes — closing the borrowed→owned→borrowed loop so
    // an owned value reaches the borrowed-only `encode`. Every sidecar-
    // eligible codec is scalar / bytes / string (no bounded list reaches
    // this gate), so the projection is infallible.
    assert_eq!(
        owned.as_borrowed().encode_to_vec().as_slice(), expected,
        "<sce:test-vector> at SCXML L51: as_borrowed re-encode mismatch"
    );
}
#[test]
fn test_vector_frame_l55() {
    let actual = Frame {
        sn: 0x7fu64,
        payload: (b"\xaa\xbb\xcc").into(),
    };
    let encoded = actual.encode_to_vec();
    let expected: &[u8] = &[0x7fu8, 0xaau8, 0xbbu8, 0xccu8];
    assert_eq!(
        encoded.as_slice(), expected,
        "<sce:test-vector> at SCXML L55: encode produced {:?}, expected {:?}",
        encoded, expected
    );
    let mut cursor = SceCursor::new(expected);
    let decoded = Frame::decode(&mut cursor)
        .expect("<sce:test-vector> at SCXML L55: decode failed");
    assert_eq!(
        cursor.remaining(), 0,
        "<sce:test-vector> at SCXML L55: decode left {} bytes unconsumed",
        cursor.remaining()
    );
    assert_eq!(
        decoded.sn, 0x7fu64,
        "<sce:test-vector> at SCXML L55: field `sn` mismatch"
    );
    assert_eq!(
        decoded.payload, b"\xaa\xbb\xcc",
        "<sce:test-vector> at SCXML L55: field `payload` mismatch"
    );
    // Owned-projection round-trip (acceptance #2): deep-copy the borrowed
    // decode into its no-alloc owned mirror and assert every field still
    // equals the oracle. An owned bytes or text field held within its bound
    // lends its value with the bounds, which compares against the `&[u8]` /
    // `&str` literal (docs/adr/0077 §3). `try_into_owned` is fallible (the bounded
    // copy re-checks the decode bound); the decode above already proved the
    // value fits, so the projection cannot fail here.
    let owned = Frame::decode(&mut SceCursor::new(expected))
        .expect("<sce:test-vector> at SCXML L55: decode for into_owned failed")
        .try_into_owned()
        .expect("<sce:test-vector> at SCXML L55: try_into_owned exceeded a bounded field");
    assert_eq!(
        owned.sn, 0x7fu64,
        "<sce:test-vector> at SCXML L55: into_owned field `sn` mismatch"
    );
    assert_eq!(
        owned.payload.as_bytes(), b"\xaa\xbb\xcc",
        "<sce:test-vector> at SCXML L55: into_owned field `payload` mismatch"
    );
    // Owned→borrowed projection round-trip (acceptance #2): re-borrow the
    // owned mirror back into the zero-copy view and assert it re-encodes to
    // the exact oracle bytes — closing the borrowed→owned→borrowed loop so
    // an owned value reaches the borrowed-only `encode`. Every sidecar-
    // eligible codec is scalar / bytes / string (no bounded list reaches
    // this gate), so the projection is infallible.
    assert_eq!(
        owned.as_borrowed().encode_to_vec().as_slice(), expected,
        "<sce:test-vector> at SCXML L55: as_borrowed re-encode mismatch"
    );
}
#[test]
fn test_vector_frame_l59() {
    let actual = Frame {
        sn: 0x80u64,
        payload: (b"\xde\xad").into(),
    };
    let encoded = actual.encode_to_vec();
    let expected: &[u8] = &[0x80u8, 0x01u8, 0xdeu8, 0xadu8];
    assert_eq!(
        encoded.as_slice(), expected,
        "<sce:test-vector> at SCXML L59: encode produced {:?}, expected {:?}",
        encoded, expected
    );
    let mut cursor = SceCursor::new(expected);
    let decoded = Frame::decode(&mut cursor)
        .expect("<sce:test-vector> at SCXML L59: decode failed");
    assert_eq!(
        cursor.remaining(), 0,
        "<sce:test-vector> at SCXML L59: decode left {} bytes unconsumed",
        cursor.remaining()
    );
    assert_eq!(
        decoded.sn, 0x80u64,
        "<sce:test-vector> at SCXML L59: field `sn` mismatch"
    );
    assert_eq!(
        decoded.payload, b"\xde\xad",
        "<sce:test-vector> at SCXML L59: field `payload` mismatch"
    );
    // Owned-projection round-trip (acceptance #2): deep-copy the borrowed
    // decode into its no-alloc owned mirror and assert every field still
    // equals the oracle. An owned bytes or text field held within its bound
    // lends its value with the bounds, which compares against the `&[u8]` /
    // `&str` literal (docs/adr/0077 §3). `try_into_owned` is fallible (the bounded
    // copy re-checks the decode bound); the decode above already proved the
    // value fits, so the projection cannot fail here.
    let owned = Frame::decode(&mut SceCursor::new(expected))
        .expect("<sce:test-vector> at SCXML L59: decode for into_owned failed")
        .try_into_owned()
        .expect("<sce:test-vector> at SCXML L59: try_into_owned exceeded a bounded field");
    assert_eq!(
        owned.sn, 0x80u64,
        "<sce:test-vector> at SCXML L59: into_owned field `sn` mismatch"
    );
    assert_eq!(
        owned.payload.as_bytes(), b"\xde\xad",
        "<sce:test-vector> at SCXML L59: into_owned field `payload` mismatch"
    );
    // Owned→borrowed projection round-trip (acceptance #2): re-borrow the
    // owned mirror back into the zero-copy view and assert it re-encodes to
    // the exact oracle bytes — closing the borrowed→owned→borrowed loop so
    // an owned value reaches the borrowed-only `encode`. Every sidecar-
    // eligible codec is scalar / bytes / string (no bounded list reaches
    // this gate), so the projection is infallible.
    assert_eq!(
        owned.as_borrowed().encode_to_vec().as_slice(), expected,
        "<sce:test-vector> at SCXML L59: as_borrowed re-encode mismatch"
    );
}