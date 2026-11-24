// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;

/// `hex` read into bytes, for the digests and keystreams the RFCs print.
fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    let digits: std::vec::Vec<u8> = hex.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    let mut out = [0u8; N];
    assert_eq!(digits.len(), 2 * N, "{hex}");
    for (byte, pair) in out.iter_mut().zip(digits.chunks(2)) {
        let text = core::str::from_utf8(pair).expect("ascii");
        *byte = u8::from_str_radix(text, 16).expect("hex");
    }
    out
}

/// The four digests RFC 3174 section 7.3 prints for SHA-1 (`abc`, the 448-bit message, a million
/// `a`, ten times a 64-byte block), and one message split across parts hashed as the whole.
/// Turned red by a round function, a constant, the schedule, or the padding and length of the
/// last block.
#[test]
fn sha1_gives_the_digests_rfc_3174_prints() {
    assert_eq!(
        sha1(&[b"abc"]),
        unhex::<20>("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
    assert_eq!(
        sha1(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]),
        unhex::<20>("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
    );
    let thousand = [b'a'; 1000];
    let million = [&thousand[..]; 1000];
    assert_eq!(
        sha1(&million),
        unhex::<20>("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
    );
    let block = b"0123456701234567012345670123456701234567012345670123456701234567";
    let ten = [&block[..]; 10];
    assert_eq!(
        sha1(&ten),
        unhex::<20>("dea356a2cddd90c7a7ecedc5ebb563934f460452")
    );
    assert_eq!(sha1(&[b"ab", b"", b"c"]), sha1(&[b"abc"]));
}

/// The accept value of RFC 6455 section 1.3's sample key is the one the section prints, and the
/// sample key is the base64 of the sixteen bytes `the sample nonce`. Turned red by a GUID, a hash or a base64 that
/// drifts, which every server would refuse.
#[test]
fn the_accept_value_of_the_rfc_6455_sample_key_is_the_one_it_prints() {
    assert_eq!(
        &accept_value(b"dGhlIHNhbXBsZSBub25jZQ=="),
        b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
    assert_eq!(
        &client_key(b"the sample nonce"),
        b"dGhlIHNhbXBsZSBub25jZQ=="
    );
}

/// base64 writes RFC 4648 section 10's vectors, padding included, and writes nothing past an
/// output too short for them. Turned red by a padding or an alphabet that drifts.
#[test]
fn base64_writes_the_rfc_4648_vectors() {
    for (input, text) in [
        (&b""[..], ""),
        (&b"f"[..], "Zg=="),
        (&b"fo"[..], "Zm8="),
        (&b"foo"[..], "Zm9v"),
        (&b"foob"[..], "Zm9vYg=="),
        (&b"fooba"[..], "Zm9vYmE="),
        (&b"foobar"[..], "Zm9vYmFy"),
    ] {
        let mut out = [0u8; 8];
        let written = base64_encode(input, &mut out).expect("room");
        assert_eq!(&out[..written], text.as_bytes(), "{text}");
    }
    assert_eq!(base64_encode(b"foo", &mut [0u8; 3]), None);
}

/// The request a client writes is the one zenoh's WebSocket library writes for `ws://<host>`,
/// and the server's reader takes it, answering the accept value of its key. A buffer too short for
/// it is refused rather than cut. Turned red by a header the server side does not read.
#[test]
fn a_client_request_is_written_whole_and_read_back_by_the_server() {
    let key = client_key(b"the sample nonce");
    let mut out = [0u8; 256];
    let at = SocketAddr::from(([127, 0, 0, 1], 7447));
    let len = write_request(&mut out, at, &key).expect("room");
    assert_eq!(
        &out[..len],
        &b"GET / HTTP/1.1\r\nHost: 127.0.0.1:7447\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"[..]
    );
    assert_eq!(
        read_request(&out[..len]),
        RequestRead::Upgrade {
            head_len: len,
            accept: accept_value(&key)
        }
    );
    let v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 80));
    let len = write_request(&mut out, v6, &key).expect("room");
    assert!(out[..len].starts_with(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n"));
    assert_eq!(write_request(&mut [0u8; 40], at, &key), None);
}

/// The server's reader takes the request of a client whose header names and order differ, any
/// path, and a `Connection` that names more than `upgrade`; it refuses what is no version 13
/// upgrade, and waits for a head that has not ended. Turned red by a reader that takes a request
/// RFC 6455 section 4.2.1 tells a server to refuse, or that refuses one it allows.
#[test]
fn the_server_reads_an_upgrade_request_and_refuses_what_is_none() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let request = std::format!(
        "GET /any/path HTTP/1.1\r\nhost: h:1\r\nsec-websocket-key: {key}\r\nconnection: keep-alive, Upgrade\r\nupgrade: WebSocket\r\nsec-websocket-version: 13\r\n\r\n"
    );
    assert_eq!(
        read_request(request.as_bytes()),
        RequestRead::Upgrade {
            head_len: request.len(),
            accept: *b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        }
    );
    assert_eq!(
        read_request(&request.as_bytes()[..request.len() - 1]),
        RequestRead::Partial
    );
    let refused = [
        request.replace("GET ", "POST "),
        request.replace("HTTP/1.1", "HTTP/1.0"),
        request.replace("version: 13", "version: 8"),
        request.replace("keep-alive, Upgrade", "keep-alive"),
        request.replace("WebSocket", "h2c"),
        request.replace(key, "c2hvcnQ="),
        request.replace(&std::format!("sec-websocket-key: {key}\r\n"), ""),
    ];
    for text in refused {
        assert_eq!(
            read_request(text.as_bytes()),
            RequestRead::Refused,
            "{text}"
        );
    }
}

/// The client's reader takes the answer the server writes and the one zenoh's WebSocket library
/// writes (lowercase names), leaving the bytes after the head for the first frame; it refuses an
/// answer that is no upgrade, carries another accept value, or names an extension or subprotocol
/// the client did not offer. Turned red by a reader that takes a connection RFC 6455 section 4.1
/// tells the client to fail.
#[test]
fn the_client_reads_the_upgrade_answer_and_refuses_a_wrong_one() {
    let key = client_key(b"the sample nonce");
    let mut out = [0u8; 256];
    let len = write_response(&mut out, &accept_value(&key)).expect("room");
    assert_eq!(
        &out[..len],
        &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"[..]
    );
    out[len] = 0x82;
    assert_eq!(
        read_response(&out[..len + 1], &key),
        UpgradeRead::Upgraded { head_len: len }
    );
    assert_eq!(read_response(&out[..len - 2], &key), UpgradeRead::Partial);
    let lower = "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\ndate: x\r\n\r\n";
    assert_eq!(
        read_response(lower.as_bytes(), &key),
        UpgradeRead::Upgraded {
            head_len: lower.len()
        }
    );
    let refused = [
        lower.replace("101 Switching Protocols", "200 OK"),
        lower.replace("101 Switching", "1010 Switching"),
        lower.replace("xOo=", "xOp="),
        lower.replace("connection: upgrade", "connection: close"),
        lower.replace("upgrade: websocket", "upgrade: h2c"),
        lower.replace("date: x", "sec-websocket-extensions: permessage-deflate"),
        lower.replace("date: x", "sec-websocket-protocol: chat"),
    ];
    for text in refused {
        assert_eq!(
            read_response(text.as_bytes(), &key),
            UpgradeRead::Refused,
            "{text}"
        );
    }
}

/// A header written for each length form is read back as written, masked and not, and every
/// prefix of it is a header that has not all arrived. Turned red by a length form chosen or read
/// wrong, or a mask key misplaced.
#[test]
fn a_frame_head_is_read_as_it_was_written() {
    for (len, head_len) in [(0, 2), (125, 2), (126, 4), (65535, 4), (65536, 10)] {
        for mask in [None, Some([1, 2, 3, 4])] {
            let mut out = [0u8; MAX_HEAD_LEN];
            let written = write_head(&mut out, OP_BINARY, len, mask);
            let expected = head_len + if mask.is_some() { 4 } else { 0 };
            assert_eq!(written, expected, "{len} {mask:?}");
            assert_eq!(
                read_head(&out[..written]),
                HeadRead::Frame(FrameHead {
                    fin: true,
                    opcode: OP_BINARY,
                    mask,
                    head_len: written,
                    payload_len: len as u64,
                })
            );
            for cut in 0..written {
                assert_eq!(read_head(&out[..cut]), HeadRead::Partial, "{len} {cut}");
            }
        }
    }
}

/// The two frames RFC 6455 section 5.7 prints, "Hello" unmasked and masked, read as it reads
/// them, the masked payload unmasked in place. Turned red by a mask applied with the wrong key
/// byte or a header read off by one.
#[test]
fn the_rfc_6455_sample_frames_read_as_printed() {
    let unmasked = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    assert_eq!(
        read_head(&unmasked),
        HeadRead::Frame(FrameHead {
            fin: true,
            opcode: OP_TEXT,
            mask: None,
            head_len: 2,
            payload_len: 5,
        })
    );
    let mut masked = [
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    let HeadRead::Frame(head) = read_head(&masked) else {
        panic!("a whole frame");
    };
    assert_eq!(head.mask, Some([0x37, 0xfa, 0x21, 0x3d]));
    assert_eq!(head.head_len, 6);
    apply_mask(&mut masked[6..], [0x37, 0xfa, 0x21, 0x3d]);
    assert_eq!(&masked[6..], b"Hello");
    let fragment = [0x01, 0x03, 0x48, 0x65, 0x6c];
    assert!(matches!(
        read_head(&fragment),
        HeadRead::Frame(FrameHead { fin: false, .. })
    ));
}

/// What RFC 6455 allows no frame to be without an extension is refused: a reserved bit, a
/// reserved opcode, a fragmented or long control frame, a length with its top bit set. Turned
/// red by a reader that hands any of them on.
#[test]
fn a_frame_no_extension_allows_is_refused() {
    let mut top_bit = [0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0];
    for bytes in [
        &[0xC2, 0x00][..],
        &[0xA2, 0x00][..],
        &[0x83, 0x00][..],
        &[0x8B, 0x00][..],
        &[0x09, 0x00][..],
        &[0x89, 126, 0, 126][..],
        &top_bit[..],
    ] {
        assert_eq!(read_head(bytes), HeadRead::Refused, "{bytes:?}");
    }
    top_bit[2] = 0x7F;
    assert!(matches!(read_head(&top_bit), HeadRead::Frame(_)));
}

/// ChaCha20 gives the keystream RFC 8439 prints: the block of section 2.3.2 and the first test
/// vector of appendix A.1 (all-zero key, nonce and counter). Turned red by a quarter round, a
/// constant or a word order that drifts.
#[test]
fn chacha20_gives_the_blocks_rfc_8439_prints() {
    let mut key = [0u32; 8];
    for (i, word) in key.iter_mut().enumerate() {
        let base = 4 * i as u32;
        *word = u32::from_le_bytes([base as u8, base as u8 + 1, base as u8 + 2, base as u8 + 3]);
    }
    assert_eq!(
        chacha20_block(&key, [1, 0x0900_0000, 0x4a00_0000, 0]),
        unhex::<64>(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        )
    );
    assert_eq!(
        chacha20_block(&[0; 8], [0; 4]),
        unhex::<64>(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        )
    );
}

/// The mask keys are the keystream of the generator's key and nonce, four bytes at a time, one
/// block after another: never a counter, never the same block twice. Turned red by a generator
/// that hands out a key twice or leaves the keystream.
#[test]
fn mask_keys_are_the_keystream_four_bytes_at_a_time() {
    let mut keys = MaskKeys::seeded(&[0; MASK_SEED_LEN]);
    let first = chacha20_block(&[0; 8], [0; 4]);
    let second = chacha20_block(&[0; 8], [1, 0, 0, 0]);
    let drawn: std::vec::Vec<[u8; 4]> = (0..32).map(|_| keys.next_key()).collect();
    for (i, key) in drawn.iter().enumerate() {
        let block = if i < 16 { &first } else { &second };
        let at = 4 * (i % 16);
        assert_eq!(&key[..], &block[at..at + 4], "{i}");
    }
    let mut seed = [0u8; MASK_SEED_LEN];
    seed[39] = 1;
    let mut other = MaskKeys::seeded(&seed);
    assert_ne!(other.next_key(), drawn[0], "the nonce keys the stream");
}
