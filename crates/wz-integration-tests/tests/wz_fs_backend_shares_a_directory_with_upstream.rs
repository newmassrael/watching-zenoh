// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2804 — ONE DIRECTORY, TWO IMPLEMENTATIONS: wz's filesystem backend and
//! upstream's (`zenoh-backend-filesystem` 1.10.1, driven through
//! `oracles/fs-backend`) read and write the same tree, and each must serve
//! what the other wrote with its payload, encoding and timestamp.
//!
//! ## The claim, and why only this can witness it
//!
//! `storage-backend-filesystem` keeps each value as a raw file at its key's
//! path and its encoding and timestamp in `.zenoh_datainfo`, the RocksDB
//! database upstream's backend keeps beside the files, so that a directory is
//! shared with zenohd rather than merely resembling one. Every in-crate test of
//! that format compares wz against bytes DERIVED from upstream's source. None
//! of them can say whether upstream agrees -- a derivation that is wrong the
//! same way in the encoder and the decoder passes all of them. Here the other
//! side is upstream's own code: the row it wrote is decoded by wz, and the row
//! wz wrote is decoded by upstream.
//!
//! ## How each comparison is built
//!
//! The oracle prints what upstream's `Storage::get` returned as one line; wz's
//! answer is rendered into the SAME line format (`wz_line`), so a comparison is
//! a string equality over every field at once. Each leg ALSO compares against
//! the line the written values predict, because two implementations that agree
//! on a wrong answer would pass a differential alone -- the prediction is what
//! makes the agreement mean the values survived.
//!
//! The timestamp id is written as its significant little-endian bytes on both
//! sides, the form zenoh puts on the wire.
//!
//! `#[ignore]`: it needs the oracle built (`cd oracles && cargo build -p
//! wz-oracle-fs-backend --release`), which is a separate workspace linking
//! upstream. Layer E16 runs it after building that.
//!
//! Every test name starts `fs_shared_dir_`, and that is an OBLIGATION rather
//! than style: Layer E sweeps this crate's ignored tests minus `--skip` name
//! tokens, and it builds no oracle, so `fs_shared_dir` is the token that hands
//! these to E16. `layer_e_oracle_scope_gate.py` refuses a test that reaches
//! `wz_zenoh_oracle_binary` and is still selected by that sweep.

use std::path::Path;
use std::process::Command;

use wz_integration_tests::common::wz_zenoh_oracle_binary;
use wz_runtime_tokio::filesystem_storage::FilesystemVolume;
use wz_session_core::json5::Json5Value;
use wz_session_core::sample::{EncodingHint, TimestampHint};
use wz_session_core::storage_backend::{StorageBackend, StoredData};
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_volume::Volume;

/// The storage's `dir` under the volume root, the same on both sides.
const DIR: &str = "shared";

/// A timestamp far from "now", so a value that was re-stamped from a file time
/// or a clock cannot pass for the written one.
const TIME: u64 = 0x0000_0001_2345_6789;
/// A three-byte id: its significant bytes are the whole of it, and it is not
/// `[1]`, the id upstream stamps a file with no row -- so a row that was lost
/// cannot pass for one that was read.
const ZID: [u8; 3] = [0x0a, 0x0b, 0x0c];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run one oracle operation on `root`/[`DIR`], returning its stdout.
fn oracle(root: &Path, args: &[&str]) -> String {
    let out = Command::new(wz_zenoh_oracle_binary("fs-backend"))
        .env("ZENOH_BACKEND_FS_ROOT", root)
        .arg(DIR)
        .args(args)
        .output()
        .expect("spawn wz-oracle-fs-backend");
    assert!(
        out.status.success(),
        "upstream's backend refused {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("oracle output is utf-8")
}

/// wz's storage over the same directory. Dropped before the oracle runs:
/// RocksDB lets ONE process hold the sidecar, which upstream relies on too.
fn wz_storage(root: &Path) -> Box<dyn StorageBackend + Send> {
    let mut cfg = StorageConfig::new("shared", "**", "fs");
    cfg.volume_cfg
        .push((String::from("dir"), Json5Value::String(String::from(DIR))));
    FilesystemVolume::new(root)
        .create_storage(&mut cfg)
        .expect("wz opens the directory")
}

/// A value in the oracle's line format.
fn line(payload: &[u8], id: u16, schema: Option<&str>, time: u64, zid: &[u8]) -> String {
    format!(
        "value payload={} encoding={id} schema={} time={time} zid={}\n",
        hex(payload),
        schema.unwrap_or("-"),
        hex(zid)
    )
}

/// wz's answer for `key`, in the oracle's line format.
fn wz_line(root: &Path, key: Option<&str>) -> String {
    let storage = wz_storage(root);
    let found = storage.get(key).expect("wz reads the directory");
    match found.as_slice() {
        [] => String::from("absent\n"),
        [StoredData {
            payload,
            encoding,
            timestamp,
        }] => {
            let (id, schema) = match encoding {
                None => (0, None),
                Some(e) => (
                    u16::try_from(e.packed_id >> 1).expect("an encoding id is sixteen bits"),
                    e.schema.as_deref(),
                ),
            };
            line(payload, id, schema, timestamp.time, &timestamp.zid)
        }
        many => panic!("wz answered {} values for one key", many.len()),
    }
}

fn wz_put(root: &Path, key: Option<&str>, payload: &[u8], id: u16, schema: Option<&str>) {
    let mut storage = wz_storage(root);
    storage
        .put(
            key,
            payload.to_vec(),
            Some(EncodingHint {
                packed_id: (u32::from(id) << 1) | u32::from(schema.is_some()),
                schema: schema.map(String::from),
            }),
            TimestampHint {
                time: TIME,
                zid: ZID.to_vec(),
            },
        )
        .expect("wz writes the directory");
}

fn oracle_put(root: &Path, key: &str, payload: &[u8], id: u16, schema: Option<&str>) {
    let out = oracle(
        root,
        &[
            "put",
            key,
            &hex(payload),
            &id.to_string(),
            schema.unwrap_or("-"),
            &TIME.to_string(),
            &hex(&ZID),
        ],
    );
    assert_eq!(out, "inserted\n");
}

/// Upstream writes; wz reads every field back -- a key, a key with a schema,
/// and the `None` key upstream files as `@root`.
// wz-proves: storage-backend-filesystem zenoh->wz
#[test]
#[ignore = "needs oracles/fs-backend (upstream zenoh-backend-filesystem 1.10.1); Layer E16 runs it via --ignored"]
fn fs_shared_dir_a_value_upstream_wrote_is_served_by_wz_with_its_encoding_and_timestamp() {
    let root = tempfile::tempdir().expect("tempdir");
    oracle_put(root.path(), "demo/a", b"from upstream", 10, None);
    oracle_put(root.path(), "demo/b", b"{}", 5, Some("with-schema"));
    oracle_put(root.path(), "@", b"at the prefix", 7, None);

    for (key, wz_key, payload, id, schema) in [
        ("demo/a", Some("demo/a"), &b"from upstream"[..], 10, None),
        ("demo/b", Some("demo/b"), &b"{}"[..], 5, Some("with-schema")),
        ("@", None, &b"at the prefix"[..], 7, None),
    ] {
        let want = line(payload, id, schema, TIME, &ZID);
        assert_eq!(
            oracle(root.path(), &["get", key]),
            want,
            "upstream reads its own {key}"
        );
        assert_eq!(
            wz_line(root.path(), wz_key),
            want,
            "wz reads upstream's {key}"
        );
    }
}

/// wz writes; upstream reads every field back.
// wz-proves: storage-backend-filesystem wz->zenoh
#[test]
#[ignore = "needs oracles/fs-backend (upstream zenoh-backend-filesystem 1.10.1); Layer E16 runs it via --ignored"]
fn fs_shared_dir_a_value_wz_wrote_is_served_by_upstream_with_its_encoding_and_timestamp() {
    let root = tempfile::tempdir().expect("tempdir");
    wz_put(root.path(), Some("demo/a"), b"from wz", 10, None);
    wz_put(root.path(), Some("demo/b"), b"{}", 5, Some("with-schema"));
    wz_put(root.path(), None, b"at the prefix", 7, None);

    for (key, payload, id, schema) in [
        ("demo/a", &b"from wz"[..], 10, None),
        ("demo/b", &b"{}"[..], 5, Some("with-schema")),
        ("@", &b"at the prefix"[..], 7, None),
    ] {
        assert_eq!(
            oracle(root.path(), &["get", key]),
            line(payload, id, schema, TIME, &ZID),
            "upstream reads wz's {key}"
        );
    }
}

/// A key that is a prefix of another is filed under a conflict name, and the
/// move happens with its row. Each side lays down one half: the file that
/// moves aside was written by one implementation and moved by the other.
// wz-proves: storage-backend-filesystem wz->zenoh
// wz-proves: storage-backend-filesystem zenoh->wz
#[test]
#[ignore = "needs oracles/fs-backend (upstream zenoh-backend-filesystem 1.10.1); Layer E16 runs it via --ignored"]
fn fs_shared_dir_a_prefix_conflict_laid_down_by_one_side_is_read_by_the_other() {
    let root = tempfile::tempdir().expect("tempdir");
    // upstream writes the short key, wz the long one: wz moves upstream's
    // file aside, row and all, and upstream must still find it.
    oracle_put(root.path(), "p", b"short", 1, None);
    wz_put(root.path(), Some("p/q"), b"long", 2, None);
    assert_eq!(
        oracle(root.path(), &["get", "p"]),
        line(b"short", 1, None, TIME, &ZID)
    );
    assert_eq!(
        oracle(root.path(), &["get", "p/q"]),
        line(b"long", 2, None, TIME, &ZID)
    );

    // and the other way round.
    wz_put(root.path(), Some("r"), b"short", 3, None);
    oracle_put(root.path(), "r/s", b"long", 4, None);
    assert_eq!(
        wz_line(root.path(), Some("r")),
        line(b"short", 3, None, TIME, &ZID)
    );
    assert_eq!(
        wz_line(root.path(), Some("r/s")),
        line(b"long", 4, None, TIME, &ZID)
    );
}

/// A file nobody put has no row, and both backends then fall back the same
/// way: the encoding guessed from the extension and the file's modification
/// time, stamped with id `[1]`. The comparison is purely differential -- the
/// time is the file system's -- so the predicted half is the id.
// wz-proves: storage-backend-filesystem zenoh->wz
#[test]
#[ignore = "needs oracles/fs-backend (upstream zenoh-backend-filesystem 1.10.1); Layer E16 runs it via --ignored"]
fn fs_shared_dir_a_file_nobody_put_reads_the_same_through_both() {
    let root = tempfile::tempdir().expect("tempdir");
    // Let upstream create the directory and its sidecar first, then drop an
    // operator's file into it.
    oracle_put(root.path(), "seed", b"x", 1, None);
    std::fs::write(root.path().join(DIR).join("page.json"), b"{\"k\":1}").unwrap();

    let upstream = oracle(root.path(), &["get", "page.json"]);
    assert!(
        upstream.ends_with(" zid=01\n"),
        "upstream stamps a file with no row with id [1]: {upstream}"
    );
    assert_eq!(wz_line(root.path(), Some("page.json")), upstream);
}

/// A delete by one side is seen by the other: the file AND its row go, so
/// neither a read nor a listing finds the key.
///
/// The row's removal is not visible while the file is absent -- upstream reads
/// no row for a file that is not there -- so the last step puts an operator's
/// file back at the deleted key. A row left behind would then lend that file
/// the deleted value's timestamp and encoding; with the row gone, upstream
/// stamps it as a file with no row, id `[1]`.
// wz-proves: storage-backend-filesystem wz->zenoh
#[test]
#[ignore = "needs oracles/fs-backend (upstream zenoh-backend-filesystem 1.10.1); Layer E16 runs it via --ignored"]
fn fs_shared_dir_a_delete_by_wz_is_seen_by_upstream() {
    let root = tempfile::tempdir().expect("tempdir");
    oracle_put(root.path(), "gone", b"x", 1, None);
    oracle_put(root.path(), "kept", b"y", 2, None);
    wz_storage(root.path())
        .delete(
            Some("gone"),
            TimestampHint {
                time: TIME + 1,
                zid: ZID.to_vec(),
            },
        )
        .expect("wz deletes");
    assert_eq!(oracle(root.path(), &["get", "gone"]), "absent\n");
    assert_eq!(
        oracle(root.path(), &["entries"]),
        format!("entry key=kept time={TIME} zid={}\n", hex(&ZID)),
        "upstream lists exactly what is left"
    );

    std::fs::write(root.path().join(DIR).join("gone"), b"back").unwrap();
    let reread = oracle(root.path(), &["get", "gone"]);
    assert!(
        reread.starts_with(&format!("value payload={} ", hex(b"back")))
            && reread.ends_with(" zid=01\n"),
        "the deleted key's row outlived its file: {reread}"
    );
}
