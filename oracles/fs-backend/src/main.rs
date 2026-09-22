// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2803 — one operation on a storage of upstream's filesystem backend, with
//! its result printed in a form a fixture can compare field by field.
//!
//! ## What makes it a FOREIGN witness
//!
//! Every byte this program leaves on disk, and every value it reports reading,
//! comes from `zenoh-backend-filesystem` 1.10.1: its volume (`Plugin::start`,
//! which derives the root from `ZENOH_BACKEND_FS_ROOT` exactly as zenohd's
//! does), its `create_storage` (which reads the storage's `dir`), and its
//! `Storage` impl (the raw file per key plus the `.zenoh_datainfo` row). The
//! storage configuration goes through upstream's own parser
//! (`PluginConfig::try_from`), the path a `zenohd -c` config takes. This
//! program chooses VALUES -- a key, a payload, an encoding, a timestamp -- and
//! nothing else.
//!
//! ## Interface
//!
//! ```text
//! ZENOH_BACKEND_FS_ROOT=<root> wz-oracle-fs-backend <dir> put <key> <payload-hex> <encoding-id> <schema|-> <ntp64> <zid-hex>
//! ZENOH_BACKEND_FS_ROOT=<root> wz-oracle-fs-backend <dir> get <key>
//! ZENOH_BACKEND_FS_ROOT=<root> wz-oracle-fs-backend <dir> delete <key>
//! ZENOH_BACKEND_FS_ROOT=<root> wz-oracle-fs-backend <dir> entries
//! ```
//!
//! `<key>` `@` stands for upstream's `None` key -- the value stored AT the
//! storage's prefix, which the backend files as `@root`. Every other key is a
//! key expression. `get` prints `absent` or one `value …` line; `entries`
//! prints one `entry …` line per stored key. Anything else is an exit 2 with a
//! message, never a guess.

use std::time::Duration;

use zenoh::{
    bytes::{Encoding, ZBytes},
    internal::buffers::ZSlice,
    key_expr::OwnedKeyExpr,
    time::{Timestamp, TimestampId, NTP64},
};
// The package is `zenoh-backend-filesystem`; its library target is named
// `zenoh_backend_fs` (upstream's `[lib] name`), which is what code imports.
use zenoh_backend_fs::FileSystemBackend;
use zenoh_backend_traits::{config::PluginConfig, Storage, StorageInsertionResult};
use zenoh_plugin_trait::Plugin;

fn die(msg: &str) -> ! {
    eprintln!("fs-backend: {msg}");
    std::process::exit(2);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    if text.len() % 2 != 0 {
        die(&format!("{text:?} is not hex: odd length"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .unwrap_or_else(|_| die(&format!("{text:?} is not hex")))
        })
        .collect()
}

fn key(text: &str) -> Option<OwnedKeyExpr> {
    if text == "@" {
        return None;
    }
    Some(
        OwnedKeyExpr::try_from(text.to_string())
            .unwrap_or_else(|e| die(&format!("{text:?} is not a key expression: {e}"))),
    )
}

fn key_text(key: &Option<OwnedKeyExpr>) -> String {
    key.as_ref()
        .map_or_else(|| String::from("@"), |k| k.to_string())
}

/// The timestamp id as its significant little-endian bytes -- the form zenoh
/// puts on the wire and the form wz keeps.
fn zid_hex(stamp: &Timestamp) -> String {
    let id = stamp.get_id();
    hex(&id.to_le_bytes()[..id.size()])
}

fn arg(argv: &[String], i: usize, what: &str) -> String {
    argv.get(i)
        .cloned()
        .unwrap_or_else(|| die(&format!("missing {what}")))
}

/// A storage of upstream's fs volume over `<root>/<dir>`, configured the way a
/// `zenohd -c` document configures one, through upstream's own parser.
async fn open(dir: &str) -> Box<dyn Storage> {
    let doc = serde_json::json!({
        "volumes": { "fs": {} },
        "storages": {
            "oracle": { "key_expr": "**", "volume": { "id": "fs", "dir": dir } }
        }
    });
    let plugin = PluginConfig::try_from(("storage_manager", &doc))
        .unwrap_or_else(|e| die(&format!("upstream refused the config: {e}")));
    let volume_cfg = plugin
        .volumes
        .iter()
        .find(|v| v.name == "fs")
        .unwrap_or_else(|| die("upstream parsed no `fs` volume"));
    let storage_cfg = plugin
        .storages
        .into_iter()
        .next()
        .unwrap_or_else(|| die("upstream parsed no storage"));
    let volume = FileSystemBackend::start("fs", volume_cfg)
        .unwrap_or_else(|e| die(&format!("upstream's fs volume did not start: {e}")));
    volume
        .create_storage(storage_cfg)
        .await
        .unwrap_or_else(|e| die(&format!("upstream refused the storage: {e}")))
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let dir = arg(&argv, 0, "<dir>");
    let op = arg(&argv, 1, "<op>");
    let mut storage = open(&dir).await;
    match op.as_str() {
        "put" => {
            let k = key(&arg(&argv, 2, "<key>"));
            let payload = unhex(&arg(&argv, 3, "<payload-hex>"));
            let id: u16 = arg(&argv, 4, "<encoding-id>")
                .parse()
                .unwrap_or_else(|_| die("<encoding-id> is not a u16"));
            let schema = arg(&argv, 5, "<schema|->");
            let schema = (schema != "-").then(|| ZSlice::from(schema.into_bytes()));
            let time: u64 = arg(&argv, 6, "<ntp64>")
                .parse()
                .unwrap_or_else(|_| die("<ntp64> is not a u64"));
            let zid = TimestampId::try_from(&unhex(&arg(&argv, 7, "<zid-hex>"))[..])
                .unwrap_or_else(|e| die(&format!("<zid-hex> is not a timestamp id: {e}")));
            let stamp = Timestamp::new(NTP64(time), zid);
            match storage
                .put(k, ZBytes::from(payload), Encoding::new(id, schema), stamp)
                .await
            {
                Ok(StorageInsertionResult::Inserted) => println!("inserted"),
                Ok(other) => println!("put answered {other:?}"),
                Err(e) => die(&format!("put failed: {e}")),
            }
        }
        "get" => {
            let k = key(&arg(&argv, 2, "<key>"));
            let found = storage
                .get(k, "")
                .await
                .unwrap_or_else(|e| die(&format!("get failed: {e}")));
            match found.as_slice() {
                [] => println!("absent"),
                [one] => println!(
                    "value payload={} encoding={} schema={} time={} zid={}",
                    hex(&one.payload.to_bytes()),
                    one.encoding.id(),
                    one.encoding.schema().map_or_else(
                        || String::from("-"),
                        |s| String::from_utf8_lossy(s).into_owned()
                    ),
                    one.timestamp.get_time().as_u64(),
                    zid_hex(&one.timestamp),
                ),
                many => die(&format!("get answered {} values for one key", many.len())),
            }
        }
        "delete" => {
            let k = key(&arg(&argv, 2, "<key>"));
            // The delete's timestamp is not stored by this backend -- upstream
            // removes the file and its row -- so any value serves.
            let stamp = Timestamp::new(NTP64::from(Duration::from_secs(1)), TimestampId::rand());
            match storage.delete(k, stamp).await {
                Ok(StorageInsertionResult::Deleted) => println!("deleted"),
                Ok(other) => println!("delete answered {other:?}"),
                Err(e) => die(&format!("delete failed: {e}")),
            }
        }
        "entries" => {
            let entries = storage
                .get_all_entries()
                .await
                .unwrap_or_else(|e| die(&format!("get_all_entries failed: {e}")));
            for (k, stamp) in &entries {
                println!(
                    "entry key={} time={} zid={}",
                    key_text(k),
                    stamp.get_time().as_u64(),
                    zid_hex(stamp)
                );
            }
        }
        other => die(&format!("unknown op {other:?}")),
    }
}
