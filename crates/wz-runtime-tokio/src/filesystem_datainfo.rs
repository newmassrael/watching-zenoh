// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 filesystem storage — the `.zenoh_datainfo` sidecar.
//!
//! R2801. A value the filesystem backend stores is a RAW FILE at its key's
//! path (see [`crate::filesystem_keypath`]), so the file itself cannot say what
//! encoding the value was published with or which timestamp versioned it.
//! zenoh's filesystem backend keeps both in a RocksDB database in a directory
//! named `.zenoh_datainfo` inside the storage's base directory, keyed by each
//! file's path; a file with no row there was not put through zenoh, and its
//! encoding is guessed from its extension and its timestamp read off its
//! modification time.
//!
//! This module IS that database, byte-compatible, and not a wz sidecar under
//! another name. The reason is the owner's full-parity decision for this
//! backend's shape (R2573): a directory is only a mirror of the key space if
//! either implementation can serve what the other wrote, and the metadata is
//! the half of a value a raw file cannot carry. A wz-native sidecar would have
//! left two failures, both silent: a storage directory zenohd wrote would reopen
//! under wz with every encoding re-guessed and every timestamp replaced by a
//! file time -- and a timestamp is what the newer-wins gate and every aligning
//! peer compare, so the values would look NEWER than the peers' own copies of
//! them -- and a directory wz wrote would reopen under zenohd the same way.
//! Taking the name with a DIFFERENT format was never an option at all:
//! zenohd opens whatever sits at that path as a RocksDB database and refuses to
//! create the storage when it cannot.
//!
//! ## The row, read from the counterparty at the matching version
//!
//! `zenoh-backend-filesystem` 1.10.1, the tag matching this tree's zenoh pin.
//! Its data-info module (symbols `DataInfoMgr`, `DataInfo::as_tuple`,
//! `DataInfo::from_tuple`, `decode_encoding_timestamp_from_value`) defines:
//!
//! - the database: `DB::open_default` on `<base_dir>/.zenoh_datainfo`;
//! - the KEY: the file's path as `to_string_lossy()` -- the path the backend
//!   joined onto its base directory, suffix included for a conflict-renamed
//!   file;
//! - the VALUE: the zenoh-serialized tuple `(u64, [u8; 16], u16, Vec<u8>)` =
//!   (timestamp time, timestamp id as 16 little-endian bytes, encoding id,
//!   encoding schema bytes, empty meaning none).
//!
//! The serialization is zenoh-ext's, read at the zenoh pin
//! (`zenoh-ext/src/serialization.rs` @ `macro_rules! impl_num {`): integers are
//! little-endian at their width, a fixed array and a vector are both prefixed
//! with their length as an unsigned LEB128 varint, and a tuple is its fields in
//! order. Decoding refuses trailing bytes
//! (`zenoh-ext/src/serialization.rs` @ `if !deserializer.done() {`), and a
//! fixed array whose prefix is not exactly its length.
//!
//! ⚠ The counterparty's paths are DESCRIBED here rather than cited: the
//! citation gate anchors on the zenoh monorepo's roots, and a separate
//! repository's path would sit in no budget -- the same limit
//! [`crate::filesystem_keypath`] records.
//!
//! ## Where wz departs, and in which direction
//!
//! - **Writes are synchronous.** Upstream writes under RocksDB's default
//!   options, which do not fsync the write-ahead log, so a power loss can drop a
//!   row whose file survived. wz's backend is `Durable` and fsyncs everything
//!   else it writes, so every row write here sets `sync`. The bytes are the
//!   same; only the durability is stronger.
//! - **A row wz cannot represent is refused, not approximated.** wz carries an
//!   encoding schema as UTF-8 text and a timestamp id as its significant bytes;
//!   a row whose schema is not UTF-8 is a read error rather than a lossy
//!   conversion, and a timestamp id that is empty or longer than sixteen bytes is
//!   refused on write because upstream's id cannot hold it (a zero id is not an
//!   id at all -- `TimestampId` is non-zero).

use std::path::Path;

use rocksdb::{WriteOptions, DB};

use wz_session_core::encoding::EncodingId;
use wz_session_core::sample::{EncodingHint, TimestampHint};

/// The sidecar's directory name inside a storage's base directory — byte for
/// byte upstream's `DataInfoMgr::DB_FILENAME`. A directory walk over the
/// storage must never read what is under it as keys.
pub const DB_FILENAME: &str = ".zenoh_datainfo";

/// The width of upstream's timestamp id (`uhlc::ID::MAX_SIZE`, a `u128`).
const ID_BYTES: usize = 16;

/// What the sidecar knows about one file: the two things a raw file cannot
/// carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataInfo {
    /// The encoding the value was put with. `None` is zenoh's default encoding
    /// (id 0, no schema) -- upstream's `Encoding` is never absent, and its
    /// default is what an absent wz encoding means on the wire.
    pub encoding: Option<EncodingHint>,
    /// The timestamp that versioned the value.
    pub timestamp: TimestampHint,
}

/// Why a row could not be written or read.
#[derive(Debug)]
pub enum DataInfoError {
    /// The database refused the operation.
    Db(rocksdb::Error),
    /// A stored row is not a well-formed upstream tuple, or holds a value wz
    /// cannot represent. The text names which.
    Corrupt(&'static str),
    /// A value handed in has no representation in upstream's row. The text
    /// names which field.
    Unrepresentable(&'static str),
}

impl core::fmt::Display for DataInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DataInfoError::Db(e) => write!(f, "data-info database: {e}"),
            DataInfoError::Corrupt(why) => write!(f, "corrupt data-info row: {why}"),
            DataInfoError::Unrepresentable(why) => {
                write!(f, "value has no data-info representation: {why}")
            }
        }
    }
}

impl From<rocksdb::Error> for DataInfoError {
    fn from(e: rocksdb::Error) -> Self {
        DataInfoError::Db(e)
    }
}

/// The key a file's row lives under: upstream's `file.as_ref().to_string_lossy()`.
fn row_key(file: &Path) -> Vec<u8> {
    file.to_string_lossy().into_owned().into_bytes()
}

/// A synchronous write, for the reason the module note gives.
fn sync_write() -> WriteOptions {
    let mut wo = WriteOptions::default();
    wo.set_sync(true);
    wo
}

/// The open sidecar of one storage directory.
///
/// RocksDB holds a lock file for as long as the database is open, so at most
/// ONE live store per directory is now enforced rather than documented: a second
/// open of the same directory -- in this process or another, zenohd included --
/// is refused while this one lives.
pub struct DataInfoStore {
    db: DB,
}

impl core::fmt::Debug for DataInfoStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DataInfoStore")
            .field("path", &self.db.path())
            .finish()
    }
}

impl DataInfoStore {
    /// Open (creating if absent) the sidecar of the storage rooted at
    /// `base_dir` -- upstream's `DB::open_default` on the same path, so the
    /// options (and with them the on-disk format) are upstream's too.
    pub fn open(base_dir: &Path) -> Result<Self, DataInfoError> {
        Ok(Self {
            db: DB::open_default(base_dir.join(DB_FILENAME))?,
        })
    }

    /// Record `info` for `file`.
    pub fn put(&self, file: &Path, info: &DataInfo) -> Result<(), DataInfoError> {
        let value = encode(info)?;
        self.db.put_opt(row_key(file), value, &sync_write())?;
        Ok(())
    }

    /// The row for `file`, or `None` when the file was not put through zenoh.
    pub fn get(&self, file: &Path) -> Result<Option<DataInfo>, DataInfoError> {
        match self.db.get_pinned(row_key(file))? {
            Some(value) => decode(value.as_ref()).map(Some),
            None => Ok(None),
        }
    }

    /// Forget `file`. Upstream keeps no tombstone here -- the version of a
    /// delete is the storage service's to remember, not the medium's.
    pub fn delete(&self, file: &Path) -> Result<(), DataInfoError> {
        self.db.delete_opt(row_key(file), &sync_write())?;
        Ok(())
    }

    /// Move `from`'s row to `to`, as upstream's `rename_key` does when a file
    /// is renamed aside to make room for a directory. `Ok(false)` when `from`
    /// has no row -- upstream answers that with an error its caller turns into
    /// the file-metadata fallback, and this says the same thing without
    /// pretending it failed.
    pub fn rename(&self, from: &Path, to: &Path) -> Result<bool, DataInfoError> {
        let from_key = row_key(from);
        let Some(value) = self.db.get_pinned(&from_key)?.map(|v| v.to_vec()) else {
            return Ok(false);
        };
        self.db.put_opt(row_key(to), value, &sync_write())?;
        self.db.delete_opt(from_key, &sync_write())?;
        Ok(true)
    }
}

/// Append `n` as an unsigned LEB128 varint — zenoh-ext's `VarInt<usize>`.
fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A bounds-checked reader over one row.
struct Row<'a> {
    buf: &'a [u8],
}

impl<'a> Row<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DataInfoError> {
        if n > self.buf.len() {
            return Err(DataInfoError::Corrupt("row is shorter than its fields"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// An unsigned LEB128 varint, refused when it overflows 64 bits (the
    /// `leb128` crate's own bound, which zenoh-ext reads with).
    fn varint(&mut self) -> Result<u64, DataInfoError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.take(1)?[0];
            if shift == 63 && byte > 1 {
                return Err(DataInfoError::Corrupt("length prefix overflows 64 bits"));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(DataInfoError::Corrupt("length prefix overflows 64 bits"));
            }
        }
    }

    fn length(&mut self) -> Result<usize, DataInfoError> {
        usize::try_from(self.varint()?)
            .map_err(|_| DataInfoError::Corrupt("length prefix does not fit usize"))
    }
}

/// Serialize `info` as upstream's row. Refused when a field has no
/// representation there (see the module note).
pub fn encode(info: &DataInfo) -> Result<Vec<u8>, DataInfoError> {
    let zid = &info.timestamp.zid;
    if zid.len() > ID_BYTES {
        return Err(DataInfoError::Unrepresentable(
            "timestamp id is longer than sixteen bytes",
        ));
    }
    if zid.iter().all(|&b| b == 0) {
        return Err(DataInfoError::Unrepresentable(
            "timestamp id is zero, and a zenoh timestamp id is never zero",
        ));
    }
    let (id, schema): (EncodingId, &[u8]) = match &info.encoding {
        None => (0, &[]),
        Some(enc) => {
            let id = EncodingId::try_from(enc.packed_id >> 1).map_err(|_| {
                DataInfoError::Unrepresentable("encoding id does not fit sixteen bits")
            })?;
            (id, enc.schema.as_deref().unwrap_or("").as_bytes())
        }
    };

    let mut out = Vec::with_capacity(8 + 1 + ID_BYTES + 2 + 1 + schema.len());
    out.extend_from_slice(&info.timestamp.time.to_le_bytes());
    write_varint(&mut out, ID_BYTES as u64);
    let mut id_bytes = [0u8; ID_BYTES];
    id_bytes[..zid.len()].copy_from_slice(zid);
    out.extend_from_slice(&id_bytes);
    out.extend_from_slice(&id.to_le_bytes());
    write_varint(&mut out, schema.len() as u64);
    out.extend_from_slice(schema);
    Ok(out)
}

/// Parse upstream's row.
///
/// The timestamp id comes back as its SIGNIFICANT bytes -- sixteen little-endian
/// bytes with the trailing zeros dropped, which is `uhlc::ID::size` and the
/// length zenoh puts on the wire. An encoding of id 0 with no schema is zenoh's
/// default and comes back as `None`.
pub fn decode(bytes: &[u8]) -> Result<DataInfo, DataInfoError> {
    let mut row = Row { buf: bytes };
    let time = u64::from_le_bytes(row.take(8)?.try_into().expect("took eight"));
    if row.length()? != ID_BYTES {
        return Err(DataInfoError::Corrupt(
            "timestamp id is not a sixteen-byte array",
        ));
    }
    let id_bytes = row.take(ID_BYTES)?;
    let significant = ID_BYTES - id_bytes.iter().rev().take_while(|&&b| b == 0).count();
    if significant == 0 {
        return Err(DataInfoError::Corrupt("timestamp id is zero"));
    }
    let id = EncodingId::from_le_bytes(row.take(2)?.try_into().expect("took two"));
    let schema_len = row.length()?;
    let schema = row.take(schema_len)?;
    if !row.buf.is_empty() {
        return Err(DataInfoError::Corrupt("trailing bytes after the tuple"));
    }
    let schema = if schema.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(schema.to_vec())
                .map_err(|_| DataInfoError::Corrupt("encoding schema is not UTF-8"))?,
        )
    };
    let encoding = match (id, schema) {
        (0, None) => None,
        (id, schema) => Some(EncodingHint {
            packed_id: (u32::from(id) << 1) | u32::from(schema.is_some()),
            schema,
        }),
    };
    Ok(DataInfo {
        encoding,
        timestamp: TimestampHint {
            time,
            zid: id_bytes[..significant].to_vec(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn info(zid: &[u8], encoding: Option<EncodingHint>) -> DataInfo {
        DataInfo {
            encoding,
            timestamp: TimestampHint {
                time: 0x0102_0304_0506_0708,
                zid: zid.to_vec(),
            },
        }
    }

    fn json_utf8() -> Option<EncodingHint> {
        Some(EncodingHint {
            packed_id: (5 << 1) | 1,
            schema: Some("utf-8".to_string()),
        })
    }

    /// The row's BYTES, derived field by field from the two upstream sources the
    /// module note names -- `DataInfo::as_tuple`'s field order and zenoh-ext's
    /// encoding of each field -- rather than from this module's own encoder, so
    /// the encoder cannot pass by agreeing with itself.
    #[test]
    fn a_row_is_upstreams_serialized_tuple_byte_for_byte() {
        let expected: Vec<u8> = [
            // u64 time, little-endian
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01][..],
            // [u8; 16]: LEB128 length 16, then the id little-endian, zero-padded
            &[0x10, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // u16 encoding id 5 (application/json), little-endian
            &[0x05, 0x00],
            // Vec<u8> schema: LEB128 length 5, then "utf-8"
            &[0x05, b'u', b't', b'f', b'-', b'8'],
        ]
        .concat();
        let row = info(&[0xaa, 0xbb], json_utf8());
        assert_eq!(encode(&row).unwrap(), expected);
        assert_eq!(decode(&expected).unwrap(), row);
    }

    #[test]
    fn the_default_encoding_is_id_zero_with_an_empty_schema_both_ways() {
        let row = info(&[0x01], None);
        let bytes = encode(&row).unwrap();
        assert_eq!(&bytes[25..], &[0x00, 0x00, 0x00], "id 0, schema length 0");
        assert_eq!(decode(&bytes).unwrap().encoding, None);
    }

    #[test]
    fn an_id_reads_back_as_its_significant_bytes() {
        // Sixteen little-endian bytes on disk, the trailing zeros dropped on the
        // way back -- the length zenoh puts on the wire (`uhlc::ID::size`).
        let full: Vec<u8> = (1..=16).collect();
        assert_eq!(
            decode(&encode(&info(&full, None)).unwrap())
                .unwrap()
                .timestamp
                .zid,
            full
        );
        assert_eq!(
            decode(&encode(&info(&[0x07, 0x00, 0x09], None)).unwrap())
                .unwrap()
                .timestamp
                .zid,
            vec![0x07, 0x00, 0x09],
            "an interior zero is significant; only the trailing run is not"
        );
    }

    #[test]
    fn a_long_schema_takes_a_multi_byte_length_prefix() {
        let schema = "s".repeat(200);
        let row = info(
            &[0x01],
            Some(EncodingHint {
                packed_id: (0xffff << 1) | 1,
                schema: Some(schema.clone()),
            }),
        );
        let bytes = encode(&row).unwrap();
        // 200 = 0xc8 -> LEB128 [0xc8, 0x01]
        assert_eq!(&bytes[27..29], &[0xc8, 0x01]);
        assert_eq!(decode(&bytes).unwrap(), row);
    }

    #[test]
    fn a_timestamp_upstream_cannot_hold_is_refused_on_write() {
        for zid in [&[][..], &[0u8, 0][..], &[1u8; 17][..]] {
            assert!(
                matches!(
                    encode(&info(zid, None)),
                    Err(DataInfoError::Unrepresentable(_))
                ),
                "zid {zid:?} must be refused"
            );
        }
    }

    #[test]
    fn a_malformed_row_is_refused_on_read() {
        let good = encode(&info(&[0x01], json_utf8())).unwrap();
        // trailing byte
        assert!(decode(&[good.as_slice(), &[0]].concat()).is_err());
        // truncated
        assert!(decode(&good[..good.len() - 1]).is_err());
        // an id array whose prefix is not sixteen
        let mut wrong_len = good.clone();
        wrong_len[8] = 0x0f;
        assert!(decode(&wrong_len).is_err());
        // a zero id
        let zero_id = [&good[..9], &[0u8; 16][..], &good[25..]].concat();
        assert!(decode(&zero_id).is_err());
        // a schema that is not UTF-8
        let mut bad_utf8 = good.clone();
        let n = bad_utf8.len();
        bad_utf8[n - 1] = 0xff;
        assert!(decode(&bad_utf8).is_err());
    }

    #[test]
    fn rows_round_trip_through_the_database_under_the_files_path() {
        let dir = tempdir().unwrap();
        let store = DataInfoStore::open(dir.path()).unwrap();
        let a = dir.path().join("demo/a");
        let b = dir.path().join("demo/b");
        let row = info(&[0x0a], json_utf8());
        store.put(&a, &row).unwrap();
        assert_eq!(store.get(&a).unwrap(), Some(row.clone()));
        assert_eq!(store.get(&b).unwrap(), None, "no row is not an error");

        assert!(store.rename(&a, &b).unwrap());
        assert_eq!(store.get(&a).unwrap(), None);
        assert_eq!(store.get(&b).unwrap(), Some(row));
        assert!(!store.rename(&a, &b).unwrap(), "nothing left to move");

        store.delete(&b).unwrap();
        assert_eq!(store.get(&b).unwrap(), None);
        assert!(dir.path().join(DB_FILENAME).is_dir());
    }

    #[test]
    fn rows_survive_a_reopen() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("k");
        let row = info(&[0x0b], None);
        {
            let store = DataInfoStore::open(dir.path()).unwrap();
            store.put(&a, &row).unwrap();
        }
        let store = DataInfoStore::open(dir.path()).unwrap();
        assert_eq!(store.get(&a).unwrap(), Some(row));
    }

    #[test]
    fn a_second_live_open_of_one_directory_is_refused() {
        // The one-instance-per-directory contract the old backend could only
        // document: RocksDB's lock file enforces it.
        let dir = tempdir().unwrap();
        let first = DataInfoStore::open(dir.path()).unwrap();
        assert!(matches!(
            DataInfoStore::open(dir.path()),
            Err(DataInfoError::Db(_))
        ));
        drop(first);
        assert!(
            DataInfoStore::open(dir.path()).is_ok(),
            "the lock is released when the store is dropped"
        );
    }
}
