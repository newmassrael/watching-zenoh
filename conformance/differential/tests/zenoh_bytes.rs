// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `bytes` module (the first slice of the top crate): upstream's crate (`up_zenoh`)
//! and wz's (`wz_zenoh`) given the same payloads and the same encodings, results equal as text.
//!
//! * `ZBytes` BUILT from every source it has (arrays, vectors, slices, strings, `Cow`s, the
//!   `bytes` crate's buffer, a reader, a writer with chunks and appended payloads, the options
//!   wrapper), then asked for its length, its bytes, its string (with the error of invalid UTF-8,
//!   also across a slice boundary), its slices and its debug text;
//! * the READER: reads of every size, seeks to every kind of position (a negative one, one past the
//!   end), `remaining` and `is_empty` after each step;
//! * the WRITER: writes in chunks, appends, flush, and `finish` after each;
//! * `Encoding`: every constant, built from every string of a grid (known identifiers with and
//!   without a schema, custom ones, empty, a lone separator, several separators) and from every
//!   identifier of the protocol with schemas that are and are not UTF-8, its text, its `Cow`, its
//!   schema set again, the order in which equal ones hash alike;
//! * the payload of a protocol attachment, in both directions;
//!
//! The shared-memory arm (a payload that is not in shared memory has none, and one built from a
//! buffer of a provider has its buffer back) is `conformance/differential-shm/tests/zenoh_bytes_shm.rs`.
//!
//! Upstream's files derive into wz's with a header changed and nothing else, so the differences
//! the test can see are the ones of the crates under them; none was seen in this slice.

use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    io::{Read, Seek, SeekFrom, Write},
};

use rand::{rngs::StdRng, Rng, SeedableRng};

/// A reader that fails after what it holds, and gives it in pieces of a given size.
struct Pieces {
    data: Vec<u8>,
    at: usize,
    piece: usize,
    fail_at_end: bool,
}

impl Read for Pieces {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at >= self.data.len() {
            return if self.fail_at_end {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the reader broke"))
            } else {
                Ok(0)
            };
        }
        let n = buf.len().min(self.piece).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// Text of an I/O error: its kind and its message.
fn io_text(e: &std::io::Error) -> String {
    format!("{:?}: {e}", e.kind())
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

/// Payloads the scenarios start from, by seed.
fn payloads() -> Vec<Vec<u8>> {
    let mut out = vec![
        vec![],
        vec![0],
        vec![0xff],
        b"Hello, world!".to_vec(),
        "한글 payload \u{1F600}".as_bytes().to_vec(),
        vec![0xc3],
        vec![0xe2, 0x82],
        vec![b'a', 0xc3, 0x28, b'b'],
        (0u8..=255).collect(),
    ];
    let mut rng = StdRng::seed_from_u64(0x5a_5a);
    for len in [1usize, 2, 7, 64, 255, 256, 1000, 4096, 70_000] {
        out.push((0..len).map(|_| rng.gen()).collect());
    }
    out
}

macro_rules! bytes_cases {
    ($name:ident, $z:ident, $proto:ident) => {
        mod $name {
            use super::*;
            use $z::bytes::{Encoding, OptionZBytes, ZBytes};

            fn show(z: &ZBytes) -> String {
                let slices: Vec<usize> = z.slices().map(|s| s.len()).collect();
                format!(
                    "len={} empty={} bytes={:02x?} str={} slices={slices:?}",
                    z.len(),
                    z.is_empty(),
                    z.to_bytes().iter().take(40).collect::<Vec<_>>(),
                    match z.try_to_string() {
                        Ok(s) => format!("Ok({:?})", s.chars().take(20).collect::<String>()),
                        Err(e) => format!("Err(valid_up_to={}, error_len={:?}, {e})", e.valid_up_to(), e.error_len()),
                    }
                )
            }

            /// Every way to build a payload from the same bytes.
            pub fn built() -> Vec<String> {
                let mut out = vec![];
                for (i, data) in payloads().into_iter().enumerate() {
                    let tag = format!("#{i}[{}]", data.len());
                    out.push(format!("{tag} vec: {}", show(&ZBytes::from(data.clone()))));
                    out.push(format!("{tag} &vec: {}", show(&ZBytes::from(&data))));
                    out.push(format!("{tag} slice: {}", show(&ZBytes::from(data.as_slice()))));
                    out.push(format!("{tag} cow borrowed: {}", show(&ZBytes::from(Cow::Borrowed(data.as_slice())))));
                    out.push(format!("{tag} cow owned: {}", show(&ZBytes::from(Cow::<[u8]>::Owned(data.clone())))));
                    out.push(format!("{tag} &cow: {}", show(&ZBytes::from(&Cow::Borrowed(data.as_slice())))));
                    out.push(format!("{tag} bytes: {}", show(&ZBytes::from(bytes::Bytes::from(data.clone())))));
                    if data.len() == 13 {
                        let arr: [u8; 13] = data.clone().try_into().unwrap();
                        out.push(format!("{tag} array: {}", show(&ZBytes::from(arr))));
                        out.push(format!("{tag} &array: {}", show(&ZBytes::from(&arr))));
                    }
                    if let Ok(s) = String::from_utf8(data.clone()) {
                        out.push(format!("{tag} string: {}", show(&ZBytes::from(s.clone()))));
                        out.push(format!("{tag} &string: {}", show(&ZBytes::from(&s))));
                        out.push(format!("{tag} &str: {}", show(&ZBytes::from(s.as_str()))));
                        out.push(format!("{tag} cow str: {}", show(&ZBytes::from(Cow::Borrowed(s.as_str())))));
                        out.push(format!("{tag} cow str owned: {}", show(&ZBytes::from(Cow::<str>::Owned(s.clone())))));
                        out.push(format!("{tag} &cow str: {}", show(&ZBytes::from(&Cow::Borrowed(s.as_str())))));
                    }
                    for piece in [1usize, 3, 4096] {
                        let r = Pieces { data: data.clone(), at: 0, piece, fail_at_end: false };
                        out.push(format!("{tag} reader/{piece}: {}", match ZBytes::from_reader(r) {
                            Ok(z) => show(&z),
                            Err(e) => io_text(&e),
                        }));
                    }
                    let r = Pieces { data: data.clone(), at: 0, piece: 5, fail_at_end: true };
                    out.push(format!("{tag} failing reader: {}", match ZBytes::from_reader(r) {
                        Ok(z) => show(&z),
                        Err(e) => io_text(&e),
                    }));
                    let z = ZBytes::from(data.clone());
                    out.push(format!("{tag} clone eq {} default eq {} debug {:?}", z.clone() == z, z == ZBytes::default(), format!("{z:?}").len() > 0));
                }
                out.push(format!("new: {}", show(&ZBytes::new())));
                out.push(format!("default: {}", show(&ZBytes::default())));
                out
            }

            /// Writers: chunks, appended payloads, the empty ones among them.
            pub fn written() -> Vec<String> {
                let mut out = vec![];
                let scripts: Vec<Vec<(&str, usize)>> = vec![
                    vec![],
                    vec![("w", 0)],
                    vec![("w", 5)],
                    vec![("w", 5), ("w", 7)],
                    vec![("a", 4), ("a", 0), ("a", 9)],
                    vec![("w", 3), ("a", 4), ("w", 2), ("a", 6), ("w", 10)],
                    vec![("a", 0), ("w", 0), ("a", 0)],
                    vec![("w", 1000), ("a", 1000), ("w", 1000)],
                    vec![("w", 3), ("f", 0), ("w", 3), ("f", 0), ("a", 2)],
                ];
                for (i, script) in scripts.iter().enumerate() {
                    let mut w = ZBytes::writer();
                    let mut counter = 0u8;
                    let mut log = vec![];
                    for (op, n) in script {
                        match *op {
                            "w" => {
                                let chunk: Vec<u8> = (0..*n).map(|_| { counter = counter.wrapping_add(1); counter }).collect();
                                log.push(format!("write {n} -> {:?}", w.write(&chunk).map_err(|e| io_text(&e))));
                            }
                            "a" => {
                                let chunk: Vec<u8> = (0..*n).map(|_| { counter = counter.wrapping_add(1); counter }).collect();
                                w.append(ZBytes::from(chunk));
                                log.push(format!("append {n}"));
                            }
                            _ => log.push(format!("flush {:?}", w.flush().map_err(|e| io_text(&e)))),
                        }
                    }
                    let z = w.finish();
                    out.push(format!("script {i} {log:?}: {}", show(&z)));
                    let w2 = ZBytes::writer();
                    out.push(format!("script {i} from writer: {}", show(&ZBytes::from(w2))));
                }
                let mut w = ZBytes::writer();
                w.write_all(b"some raw bytes").unwrap();
                out.push(format!("write_all: {}", show(&w.finish())));
                out
            }

            /// Readers: every read size and seek position over several payloads.
            pub fn read() -> Vec<String> {
                let mut out = vec![];
                for (i, data) in payloads().into_iter().take(12).enumerate() {
                    let z = ZBytes::from(data.clone());
                    // a writer-built payload has several slices
                    let mut w = ZBytes::writer();
                    for chunk in data.chunks(3) {
                        w.append(ZBytes::from(chunk.to_vec()));
                    }
                    let multi = w.finish();
                    for (label, z) in [("single", &z), ("multi", &multi)] {
                        for size in [0usize, 1, 2, 5, 64, 100_000] {
                            let mut r = z.reader();
                            let mut buf = vec![0u8; size];
                            let first = r.read(&mut buf).map_err(|e| io_text(&e));
                            out.push(format!(
                                "#{i} {label} read({size}) -> {first:?} remaining={} empty={}",
                                r.remaining(),
                                r.is_empty()
                            ));
                            let mut r = z.reader();
                            let mut buf = vec![0u8; size];
                            out.push(format!(
                                "#{i} {label} read_exact({size}) -> {:?} remaining={}",
                                r.read_exact(&mut buf).map_err(|e| io_text(&e)),
                                r.remaining()
                            ));
                        }
                        let n = data.len() as i64;
                        let seeks = [
                            SeekFrom::Start(0),
                            SeekFrom::Start(1),
                            SeekFrom::Start(n as u64),
                            SeekFrom::Start(n as u64 + 1),
                            SeekFrom::End(0),
                            SeekFrom::End(-1),
                            SeekFrom::End(-n),
                            SeekFrom::End(-n - 1),
                            SeekFrom::End(1),
                            SeekFrom::Current(0),
                            SeekFrom::Current(2),
                            SeekFrom::Current(-1),
                        ];
                        for seek in seeks {
                            let mut r = z.reader();
                            let mut warm = [0u8; 2];
                            let _ = r.read(&mut warm);
                            let res = r.seek(seek).map_err(|e| io_text(&e));
                            let mut rest = vec![];
                            let tail = r.read_to_end(&mut rest).map_err(|e| io_text(&e));
                            out.push(format!(
                                "#{i} {label} seek({seek:?}) -> {res:?}; rest {tail:?} {:02x?}",
                                rest.iter().take(8).collect::<Vec<_>>()
                            ));
                        }
                    }
                }
                out
            }

            /// The optional payload wrapper.
            pub fn options() -> Vec<String> {
                let mut out = vec![];
                let show_opt = |o: OptionZBytes| -> String {
                    let o: Option<ZBytes> = o.into();
                    o.map(|z| show(&z)).unwrap_or_else(|| "None".into())
                };
                out.push(format!("str: {}", show_opt("metadata".into())));
                out.push(format!("string: {}", show_opt(String::from("meta").into())));
                out.push(format!("vec: {}", show_opt(vec![1u8, 2, 3].into())));
                out.push(format!("some: {}", show_opt(Some("x").into())));
                out.push(format!("none: {}", show_opt(None::<String>.into())));
                out.push(format!("&some: {}", show_opt((&Some(String::from("y"))).into())));
                out.push(format!("&none: {}", show_opt((&None::<String>).into())));
                out.push(format!("zbytes: {}", show_opt(ZBytes::from("z").into())));
                out.push(format!("default: {:?}", show_opt(OptionZBytes::default())));
                let a: OptionZBytes = "p".into();
                let b: OptionZBytes = "p".into();
                out.push(format!("eq {} clone {}", a == b, a.clone() == b));
                out
            }

            /// `Encoding`, from strings.
            pub fn encodings_from_text() -> Vec<String> {
                let mut out = vec![];
                let known = [
                    "zenoh/bytes", "zenoh/string", "zenoh/serialized", "application/octet-stream", "text/plain",
                    "application/json", "text/json", "application/cdr", "application/cbor", "application/yaml",
                    "text/yaml", "text/json5", "application/python-serialized-object", "application/protobuf",
                    "application/java-serialized-object", "application/openmetrics-text", "image/png", "image/jpeg",
                    "image/gif", "image/bmp", "image/webp", "application/xml", "application/x-www-form-urlencoded",
                    "text/html", "text/xml", "text/css", "text/javascript", "text/markdown", "text/csv",
                    "application/sql", "application/coap-payload", "application/json-patch+json",
                    "application/json-seq", "application/jsonpath", "application/jwt", "application/mp4",
                    "application/soap+xml", "application/yang", "audio/aac", "audio/flac", "audio/mp4", "audio/ogg",
                    "audio/vorbis", "video/h261", "video/h263", "video/h264", "video/h265", "video/h266", "video/mp4",
                    "video/ogg", "video/raw", "video/vp8", "video/vp9",
                ];
                let mut texts: Vec<String> = vec![];
                for k in known {
                    texts.push(k.to_string());
                    texts.push(format!("{k};utf-8"));
                    texts.push(format!("{k};"));
                    texts.push(format!("{k};a;b"));
                }
                for t in [
                    "", ";", ";;", ";x", "x;", "my_encoding", "my/encoding;v1", "Text/Plain", " text/plain",
                    "text/plain ", "zenoh/bytes;zenoh/string", "한글/타입;스키마", "a;b;c;d", "\u{0}", "text/plain\u{0}",
                ] {
                    texts.push(t.to_string());
                }
                for t in &texts {
                    let e = Encoding::from(t.as_str());
                    let parsed: Encoding = t.parse().unwrap();
                    let s: String = e.clone().into();
                    let c: Cow<'static, str> = (&e).into();
                    out.push(format!(
                        "{t:?}: {} | id={} schema={:?} | string={s:?} cow_borrowed={} | parse eq {} | from String eq {}",
                        e,
                        e.id(),
                        e.schema().map(|z| z.len()),
                        matches!(c, Cow::Borrowed(_)),
                        parsed == e,
                        Encoding::from(t.clone()) == e,
                    ));
                    for schema in ["", "utf-8", "a;b", ";"] {
                        out.push(format!("{t:?} with_schema({schema:?}): {}", e.clone().with_schema(schema)));
                    }
                }
                out
            }

            /// `Encoding`, from the protocol's, with every identifier and some schemas.
            pub fn encodings_from_protocol() -> Vec<String> {
                let mut out = vec![];
                let schemas: Vec<Option<Vec<u8>>> = vec![
                    None,
                    Some(vec![]),
                    Some(b"utf-8".to_vec()),
                    Some(b"a;b".to_vec()),
                    Some(vec![0xff, 0xfe]),
                    Some("한글".as_bytes().to_vec()),
                    Some(b"text/plain;utf-8".to_vec()),
                ];
                let ids: Vec<u16> = (0..=60).chain([100, 1023, 1024, 0x7fff, 0xfffe, 0xffff]).collect();
                for id in ids {
                    for schema in &schemas {
                        let slice = schema.clone().map(zenoh_buffers_zslice::<_>);
                        let proto = $proto::core::Encoding { id, schema: slice.clone() };
                        let e = Encoding::from(proto.clone());
                        let c: Cow<'static, str> = (&e).into();
                        let back: $proto::core::Encoding = e.clone().into();
                        out.push(format!(
                            "id {id} schema {schema:?}: {e} borrowed={} back eq {} new eq {}",
                            matches!(c, Cow::Borrowed(_)),
                            back == proto,
                            Encoding::new(id, slice) == e,
                        ));
                        for s in ["", "utf-8", "x;y"] {
                            out.push(format!("id {id} schema {schema:?} with_schema({s:?}): {}", e.clone().with_schema(s)));
                        }
                    }
                }
                out
            }

            /// Constants, equality and hashing.
            pub fn encoding_relations() -> Vec<String> {
                let mut out = vec![];
                let all = [
                    Encoding::ZENOH_BYTES, Encoding::ZENOH_STRING, Encoding::ZENOH_SERIALIZED,
                    Encoding::APPLICATION_OCTET_STREAM, Encoding::TEXT_PLAIN, Encoding::APPLICATION_JSON,
                    Encoding::TEXT_JSON, Encoding::APPLICATION_CDR, Encoding::APPLICATION_CBOR,
                    Encoding::APPLICATION_YAML, Encoding::TEXT_YAML, Encoding::TEXT_JSON5,
                    Encoding::APPLICATION_PYTHON_SERIALIZED_OBJECT, Encoding::APPLICATION_PROTOBUF,
                    Encoding::APPLICATION_JAVA_SERIALIZED_OBJECT, Encoding::APPLICATION_OPENMETRICS_TEXT,
                    Encoding::IMAGE_PNG, Encoding::IMAGE_JPEG, Encoding::IMAGE_GIF, Encoding::IMAGE_BMP,
                    Encoding::IMAGE_WEBP, Encoding::APPLICATION_XML, Encoding::APPLICATION_X_WWW_FORM_URLENCODED,
                    Encoding::TEXT_HTML, Encoding::TEXT_XML, Encoding::TEXT_CSS, Encoding::TEXT_JAVASCRIPT,
                    Encoding::TEXT_MARKDOWN, Encoding::TEXT_CSV, Encoding::APPLICATION_SQL,
                    Encoding::APPLICATION_COAP_PAYLOAD, Encoding::APPLICATION_JSON_PATCH_JSON,
                    Encoding::APPLICATION_JSON_SEQ, Encoding::APPLICATION_JSONPATH, Encoding::APPLICATION_JWT,
                    Encoding::APPLICATION_MP4, Encoding::APPLICATION_SOAP_XML, Encoding::APPLICATION_YANG,
                    Encoding::AUDIO_AAC, Encoding::AUDIO_FLAC, Encoding::AUDIO_MP4, Encoding::AUDIO_OGG,
                    Encoding::AUDIO_VORBIS, Encoding::VIDEO_H261, Encoding::VIDEO_H263, Encoding::VIDEO_H264,
                    Encoding::VIDEO_H265, Encoding::VIDEO_H266, Encoding::VIDEO_MP4, Encoding::VIDEO_OGG,
                    Encoding::VIDEO_RAW, Encoding::VIDEO_VP8, Encoding::VIDEO_VP9,
                ];
                for (i, a) in all.iter().enumerate() {
                    out.push(format!("{i}: {a} id={} default? {}", a.id(), *a == Encoding::default()));
                    for (j, b) in all.iter().enumerate() {
                        if a == b && i != j {
                            out.push(format!("{i} and {j} are equal"));
                        }
                    }
                    let with = a.clone().with_schema("utf-8");
                    out.push(format!(
                        "{i}: with schema {with}; differs {} hash equal to its twin {}",
                        with != *a,
                        hash_of(&with) == hash_of(&a.clone().with_schema("utf-8"))
                    ));
                }
                out.push(format!("default {} {:?}", Encoding::default(), Encoding::default() == Encoding::ZENOH_BYTES));
                out.push(format!("const default {}", Encoding::default()));
                out
            }

            /// The payload of a protocol attachment.
            pub fn attachments() -> Vec<String> {
                use $proto::zenoh::ext::AttachmentType;
                let mut out = vec![];
                for data in payloads().into_iter().take(10) {
                    let z = ZBytes::from(data);
                    let a: AttachmentType<0x5> = z.clone().into();
                    let back: ZBytes = a.into();
                    out.push(format!("{} back {}", show(&z), back == z));
                }
                out
            }

        }
    };
}

/// A `ZSlice` of the crate that `$proto` is built over: the two crates have a `zenoh-buffers` of
/// their own, so the slice is made by the generic `From` of whichever type the call site wants.
fn zenoh_buffers_zslice<Z: From<Vec<u8>>>(v: Vec<u8>) -> Z {
    Z::from(v)
}

bytes_cases!(up, up_zenoh, up_protocol);
bytes_cases!(wz, wz_zenoh, wz_protocol);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 3, "{group} holds {} line(s)", up.len());
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        panic!("{group}\nupstream: {x}\nwz:       {y}");
    }
    if std::env::var_os("WZ_BYTES_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn payloads_built_from_every_source() {
    let (u, w) = (up::built(), wz::built());
    assert!(u.iter().any(|l| l.contains("Err(valid_up_to=")), "no invalid UTF-8 seen");
    compare("built", &u, &w);
}

#[test]
fn writers_chunks_and_appends() {
    compare("written", &up::written(), &wz::written());
}

#[test]
fn readers_reads_and_seeks() {
    let (u, w) = (up::read(), wz::read());
    assert!(u.iter().any(|l| l.contains("Err(")), "no failing read or seek seen");
    compare("read", &u, &w);
}

#[test]
fn the_optional_payload_wrapper() {
    compare("options", &up::options(), &wz::options());
}

#[test]
fn encodings_from_text() {
    compare("encodings from text", &up::encodings_from_text(), &wz::encodings_from_text());
}

#[test]
fn encodings_from_the_protocols() {
    compare("encodings from protocol", &up::encodings_from_protocol(), &wz::encodings_from_protocol());
}

#[test]
fn encoding_constants_equality_and_hashing() {
    let (u, w) = (up::encoding_relations(), wz::encoding_relations());
    assert!(!u.iter().any(|l| l.contains("are equal")), "two constants are equal");
    compare("relations", &u, &w);
}

#[test]
fn attachments_of_the_protocol() {
    compare("attachments", &up::attachments(), &wz::attachments());
}

#[test]
fn the_comparison_sees_a_payload_that_differs() {
    let u = up::written();
    let mut w = wz::written();
    w[3] = format!("{} changed", w[3]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::options(), vec!["x".to_string()]);
}
