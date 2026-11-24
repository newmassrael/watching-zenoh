// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ring a session's advanced publishers' caches keep their samples in together: one span of
//! bytes the session reserved at its open (`ADVANCED_CACHE_BYTES`), holding records as long as
//! their samples, each tagged with the cache it belongs to.
//!
//! A record is appended where the ring's head is, and a record that finds no room lets the oldest
//! records go from the ring's tail first, whichever cache they belong to. A cache keeps at most its
//! own `max_samples` records: past them, its own oldest record is marked dead, and its bytes come
//! back when the tail reaches it. A record never wraps: one that does not fit before the end of
//! the span is written at its start, and the span's end is remembered.
//!
//! The ring keeps its state in the first [`RING_HEAD_BYTES`] of the span, so every cache of the
//! session reads one state, and a span the session zeroed at its open is an empty ring. Every
//! field is read and written as bytes, so nothing here reads past the span whatever it holds.

use wz_session_core::sample::{EncodingRef, SampleKind, SourceInfo, TimestampHint};

use super::{Held, SampleBody};

/// The bytes the ring keeps its own state in, at the start of its span.
pub(super) const RING_HEAD_BYTES: usize = 32;

/// The bytes of a record's header, before its key.
pub(super) const RECORD_HEAD_BYTES: usize = 88;

/// What every record and the span's data start on.
const ALIGN: usize = 8;

/// The bytes a record keeps the handle of a buffer of shared memory in, when its payload is one.
#[cfg(feature = "transport-shm")]
const SHARED_BYTES: usize =
    round_up(core::mem::size_of::<wz_session_core::extshm::ShmSendHandle>());

// What a record holding a handle relies on: the handle is laid on the record's alignment.
#[cfg(feature = "transport-shm")]
const _: () = assert!(core::mem::align_of::<wz_session_core::extshm::ShmSendHandle>() <= ALIGN);

// The ring's state, at these offsets of the span.
const TAIL: usize = 0;
const HEAD: usize = 4;
const END: usize = 8;
const COUNT: usize = 12;
const NEXT_OWNER: usize = 16;
const WRAPPED: usize = 20;

// A record's header, at these offsets of the record.
const R_TOTAL: usize = 0;
const R_OWNER: usize = 4;
const R_FLAGS: usize = 8;
const R_KEY: usize = 12;
const R_PAYLOAD: usize = 16;
const R_ATTACHMENT: usize = 20;
const R_ENCODING: usize = 24;
const R_SCHEMA: usize = 28;
const R_TIME: usize = 32;
const R_TS_ZID: usize = 40;
const R_SI_ZID: usize = 56;
const R_EID: usize = 72;
const R_SN: usize = 76;
const R_TS_ZID_LEN: usize = 80;
const R_SI_ZID_LEN: usize = 81;

// What a record's flags say it holds.
const F_DEL: u32 = 1;
const F_SOURCE: u32 = 1 << 1;
const F_ENCODING: u32 = 1 << 2;
const F_SCHEMA: u32 = 1 << 3;
const F_ATTACHMENT: u32 = 1 << 4;
#[cfg(feature = "transport-shm")]
const F_SHARED: u32 = 1 << 5;

/// The owner a dead record carries: no cache's.
const DEAD: u32 = 0;

/// `n` rounded up to [`ALIGN`].
const fn round_up(n: usize) -> usize {
    match n.checked_add(ALIGN - 1) {
        Some(n) => n & !(ALIGN - 1),
        None => usize::MAX & !(ALIGN - 1),
    }
}

/// The bytes of records a span of `span` bytes holds.
pub(super) const fn capacity(span: usize) -> usize {
    span.saturating_sub(RING_HEAD_BYTES) & !(ALIGN - 1)
}

/// The bytes `body`'s record takes, padding included; `None` past the address space.
pub(super) fn record_bytes(body: &SampleBody<'_>) -> Option<usize> {
    #[cfg(feature = "transport-shm")]
    let shared = if body.shared.is_some() {
        SHARED_BYTES
    } else {
        0
    };
    #[cfg(not(feature = "transport-shm"))]
    let shared = 0;
    let schema = body
        .encoding
        .and_then(|encoding| encoding.schema)
        .map_or(0, <[u8]>::len);
    let attachment = body.attachment.map_or(0, <[u8]>::len);
    let bytes = RECORD_HEAD_BYTES
        .checked_add(shared)?
        .checked_add(body.keyexpr.len())?
        .checked_add(schema)?
        .checked_add(body.payload.len())?
        .checked_add(attachment)?;
    if bytes <= usize::MAX - ALIGN {
        Some(round_up(bytes))
    } else {
        None
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    at.checked_add(4)
        .and_then(|end| bytes.get(at..end))
        .and_then(|word| <[u8; 4]>::try_from(word).ok())
        .map_or(0, u32::from_ne_bytes)
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
    if let Some(word) = at.checked_add(4).and_then(|end| bytes.get_mut(at..end)) {
        word.copy_from_slice(&value.to_ne_bytes());
    }
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    at.checked_add(8)
        .and_then(|end| bytes.get(at..end))
        .and_then(|word| <[u8; 8]>::try_from(word).ok())
        .map_or(0, u64::from_ne_bytes)
}

fn write_u64(bytes: &mut [u8], at: usize, value: u64) {
    if let Some(word) = at.checked_add(8).and_then(|end| bytes.get_mut(at..end)) {
        word.copy_from_slice(&value.to_ne_bytes());
    }
}

/// `len` bytes at `at` of `bytes`, if they lie in it.
fn span_of(bytes: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    bytes.get(at..at.checked_add(len)?)
}

/// Copy `from` to `at` of `bytes` and answer the offset after it.
fn put_bytes(bytes: &mut [u8], at: usize, from: &[u8]) -> usize {
    let end = at.saturating_add(from.len());
    if let Some(place) = bytes.get_mut(at..end) {
        place.copy_from_slice(from);
    }
    end
}

/// A word as a `u32` the ring keeps, which a length the ring holds always is.
fn word(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// A session's ring, read and written over the bytes of its span.
pub(super) struct RecordRing<'a> {
    /// The ring's state.
    head: &'a mut [u8],
    /// The records.
    data: &'a mut [u8],
}

impl<'a> RecordRing<'a> {
    /// The ring `span` holds, or `None` for a span too short for one record of no sample, or not
    /// laid on the records' alignment.
    pub(super) fn over(span: &'a mut [u8]) -> Option<Self> {
        if span.as_ptr() as usize % ALIGN != 0 || capacity(span.len()) < RECORD_HEAD_BYTES {
            return None;
        }
        let records = capacity(span.len());
        let (head, rest) = span.split_at_mut(RING_HEAD_BYTES);
        let data = rest.get_mut(..records)?;
        Some(Self { head, data })
    }

    /// The bytes of records the ring holds.
    pub(super) fn capacity(&self) -> usize {
        self.data.len()
    }

    fn state(&self, at: usize) -> usize {
        read_u32(self.head, at) as usize
    }

    fn set_state(&mut self, at: usize, value: usize) {
        write_u32(self.head, at, word(value));
    }

    /// A new cache's owner id: one no record in the ring carries, never the dead one.
    pub(super) fn register(&mut self) -> u32 {
        let mut owner = read_u32(self.head, NEXT_OWNER);
        loop {
            owner = owner.wrapping_add(1);
            if owner != DEAD && self.live(owner) == 0 {
                break;
            }
        }
        write_u32(self.head, NEXT_OWNER, owner);
        owner
    }

    /// Call `each` with the offset of every record the ring holds, oldest first.
    fn each_record(&self, each: &mut dyn FnMut(usize)) {
        let (end, wrapped) = (self.state(END), self.state(WRAPPED) != 0);
        let mut at = self.state(TAIL);
        for _ in 0..self.state(COUNT) {
            if wrapped && at >= end {
                at = 0;
            }
            each(at);
            let total = read_u32(self.data, at.saturating_add(R_TOTAL)) as usize;
            if total == 0 {
                return;
            }
            at = at.saturating_add(total);
        }
    }

    /// How many records of `owner` the ring holds.
    pub(super) fn live(&self, owner: u32) -> usize {
        let mut live = 0usize;
        self.each_record(&mut |at| {
            if read_u32(self.data, at.saturating_add(R_OWNER)) == owner {
                live = live.saturating_add(1);
            }
        });
        live
    }

    /// The offset of `owner`'s oldest record.
    fn oldest_of(&self, owner: u32) -> Option<usize> {
        let mut oldest = None;
        self.each_record(&mut |at| {
            if oldest.is_none() && read_u32(self.data, at.saturating_add(R_OWNER)) == owner {
                oldest = Some(at);
            }
        });
        oldest
    }

    /// Mark the record at `at` dead, letting go of what it held: its bytes come back when the
    /// tail reaches it.
    fn kill(&mut self, at: usize) {
        if read_u32(self.data, at.saturating_add(R_OWNER)) == DEAD {
            return;
        }
        #[cfg(feature = "transport-shm")]
        if read_u32(self.data, at.saturating_add(R_FLAGS)) & F_SHARED != 0 {
            // SAFETY: a live record that says it holds a handle holds one, written by `write` at
            // this place, and dropping it here is the only drop it gets: the record is marked
            // dead next and read no more.
            unsafe {
                core::ptr::drop_in_place(self.shared_at(at));
            }
        }
        write_u32(self.data, at.saturating_add(R_OWNER), DEAD);
    }

    /// Let every record of `owner` go: the cache it belonged to goes.
    pub(super) fn forget(&mut self, owner: u32) {
        while let Some(at) = self.oldest_of(owner) {
            self.kill(at);
        }
    }

    /// Let the ring's oldest record go, and take back its bytes.
    fn pop_tail(&mut self) {
        let count = self.state(COUNT);
        if count == 0 {
            return;
        }
        let tail = self.state(TAIL);
        let total = read_u32(self.data, tail.saturating_add(R_TOTAL)) as usize;
        self.kill(tail);
        if total == 0 || count == 1 {
            // An empty ring, or one whose tail holds no record it can read past: either way none
            // of its records is read again.
            self.clear();
            return;
        }
        let mut next = tail.saturating_add(total);
        let wrapped = self.state(WRAPPED) != 0;
        if wrapped && next >= self.state(END) {
            next = 0;
            self.set_state(WRAPPED, 0);
        }
        self.set_state(TAIL, next);
        self.set_state(COUNT, count - 1);
    }

    /// Hold no record.
    fn clear(&mut self) {
        let mut at = self.state(TAIL);
        let (end, wrapped) = (self.state(END), self.state(WRAPPED) != 0);
        for _ in 0..self.state(COUNT) {
            if wrapped && at >= end {
                at = 0;
            }
            let total = read_u32(self.data, at.saturating_add(R_TOTAL)) as usize;
            self.kill(at);
            if total == 0 {
                break;
            }
            at = at.saturating_add(total);
        }
        for state in [TAIL, HEAD, END, COUNT, WRAPPED] {
            self.set_state(state, 0);
        }
    }

    /// The place of a new record of `need` bytes, taken: after the newest record, or at the span's
    /// start when none fits before its end. `None` while the ring has no room for it.
    fn take_room(&mut self, need: usize) -> Option<usize> {
        if self.state(COUNT) == 0 {
            for state in [TAIL, HEAD, END, WRAPPED] {
                self.set_state(state, 0);
            }
        }
        let (tail, head) = (self.state(TAIL), self.state(HEAD));
        let at = if self.state(WRAPPED) == 0 {
            if self.capacity().saturating_sub(head) >= need {
                head
            } else if tail >= need {
                self.set_state(END, head);
                self.set_state(WRAPPED, 1);
                0
            } else {
                return None;
            }
        } else if tail.saturating_sub(head) >= need {
            head
        } else {
            return None;
        };
        self.set_state(HEAD, at.saturating_add(need));
        self.set_state(COUNT, self.state(COUNT).saturating_add(1));
        Some(at)
    }

    /// Keep `body` and its stamps as a record of `owner`, which keeps at most `max_samples` of
    /// them (one at least): past them its own oldest is let go, and while the ring has no room the
    /// ring's oldest are. Nothing is kept for a record longer than the ring.
    pub(super) fn keep(
        &mut self,
        owner: u32,
        max_samples: usize,
        body: SampleBody<'_>,
        source_info: Option<SourceInfo>,
        timestamp: &TimestampHint,
    ) {
        let Some(need) = record_bytes(&body).filter(|need| *need <= self.capacity()) else {
            return;
        };
        let mut live = self.live(owner);
        while live >= max_samples.max(1) {
            match self.oldest_of(owner) {
                Some(at) => self.kill(at),
                None => break,
            }
            live -= 1;
        }
        let at = loop {
            if let Some(at) = self.take_room(need) {
                break at;
            }
            if self.state(COUNT) == 0 {
                return;
            }
            self.pop_tail();
        };
        self.write(at, need, owner, body, source_info, timestamp);
    }

    /// Write the record at `at`, of `total` bytes.
    fn write(
        &mut self,
        at: usize,
        total: usize,
        owner: u32,
        body: SampleBody<'_>,
        source_info: Option<SourceInfo>,
        timestamp: &TimestampHint,
    ) {
        let schema = body.encoding.and_then(|encoding| encoding.schema);
        let mut flags = 0;
        if matches!(body.kind, SampleKind::Del) {
            flags |= F_DEL;
        }
        if source_info.is_some() {
            flags |= F_SOURCE;
        }
        if body.encoding.is_some() {
            flags |= F_ENCODING;
        }
        if schema.is_some() {
            flags |= F_SCHEMA;
        }
        if body.attachment.is_some() {
            flags |= F_ATTACHMENT;
        }
        #[cfg(feature = "transport-shm")]
        if body.shared.is_some() {
            flags |= F_SHARED;
        }
        let data = &mut *self.data;
        write_u32(data, at + R_TOTAL, word(total));
        write_u32(data, at + R_OWNER, owner);
        write_u32(data, at + R_FLAGS, flags);
        write_u32(data, at + R_KEY, word(body.keyexpr.len()));
        write_u32(data, at + R_PAYLOAD, word(body.payload.len()));
        write_u32(
            data,
            at + R_ATTACHMENT,
            word(body.attachment.map_or(0, <[u8]>::len)),
        );
        write_u32(
            data,
            at + R_ENCODING,
            body.encoding.map_or(0, |encoding| encoding.packed_id),
        );
        write_u32(data, at + R_SCHEMA, word(schema.map_or(0, <[u8]>::len)));
        write_u64(data, at + R_TIME, timestamp.time);
        let ts_zid = timestamp.zid_prefix();
        put_bytes(data, at + R_TS_ZID, ts_zid);
        let si_zid = source_info.as_ref().map_or(&[][..], SourceInfo::zid_prefix);
        put_bytes(data, at + R_SI_ZID, si_zid);
        write_u32(
            data,
            at + R_EID,
            source_info.as_ref().map_or(0, |si| si.eid),
        );
        write_u32(data, at + R_SN, source_info.as_ref().map_or(0, |si| si.sn));
        put_bytes(
            data,
            at + R_TS_ZID_LEN,
            &[ts_zid.len() as u8, si_zid.len() as u8],
        );
        let mut off = at + RECORD_HEAD_BYTES;
        #[cfg(feature = "transport-shm")]
        if let Some(shared) = body.shared {
            // SAFETY: the record's place for a handle lies in the span, laid on its alignment
            // (`Self::over`, `ALIGN`), and holds nothing: a record is written into room the ring
            // took for it.
            unsafe { self.shared_at(at).write(shared) };
            off += SHARED_BYTES;
        }
        let data = &mut *self.data;
        off = put_bytes(data, off, body.keyexpr.as_bytes());
        if let Some(schema) = schema {
            off = put_bytes(data, off, schema);
        }
        off = put_bytes(data, off, body.payload);
        if let Some(attachment) = body.attachment {
            put_bytes(data, off, attachment);
        }
    }

    /// Where the record at `at` keeps a handle.
    #[cfg(feature = "transport-shm")]
    fn shared_at(&mut self, at: usize) -> *mut wz_session_core::extshm::ShmSendHandle {
        self.data
            .as_mut_ptr()
            .wrapping_add(at.saturating_add(RECORD_HEAD_BYTES))
            .cast()
    }

    /// Call `each` with every live sample of `owner`, oldest first.
    pub(super) fn each_of(&self, owner: u32, each: &mut dyn FnMut(Held<'_>)) {
        self.each_record(&mut |at| {
            if read_u32(self.data, at.saturating_add(R_OWNER)) == owner {
                if let Some(held) = self.held(at) {
                    each(held);
                }
            }
        });
    }

    /// The sample of the record at `at`, read where it lies.
    fn held(&self, at: usize) -> Option<Held<'_>> {
        let data: &[u8] = self.data;
        let flags = read_u32(data, at + R_FLAGS);
        let key_len = read_u32(data, at + R_KEY) as usize;
        let payload_len = read_u32(data, at + R_PAYLOAD) as usize;
        let attachment_len = read_u32(data, at + R_ATTACHMENT) as usize;
        let schema_len = read_u32(data, at + R_SCHEMA) as usize;
        let ts_zid_len = usize::from(*data.get(at + R_TS_ZID_LEN)?);
        let si_zid_len = usize::from(*data.get(at + R_SI_ZID_LEN)?);
        let timestamp = TimestampHint::new(
            read_u64(data, at + R_TIME),
            span_of(data, at + R_TS_ZID, ts_zid_len)?,
        )?;
        let source_info = if flags & F_SOURCE != 0 {
            Some(SourceInfo::new(
                span_of(data, at + R_SI_ZID, si_zid_len)?,
                read_u32(data, at + R_EID),
                read_u32(data, at + R_SN),
            ))
        } else {
            None
        };
        let mut off = at + RECORD_HEAD_BYTES;
        #[cfg(feature = "transport-shm")]
        let shared = if flags & F_SHARED != 0 {
            // SAFETY: a live record that says it holds a handle holds one at this place, laid on
            // its alignment, until it is killed, which takes the ring mutably.
            let shared = unsafe {
                &*self
                    .data
                    .as_ptr()
                    .wrapping_add(off)
                    .cast::<wz_session_core::extshm::ShmSendHandle>()
            };
            off += SHARED_BYTES;
            Some(shared)
        } else {
            None
        };
        let keyexpr = core::str::from_utf8(span_of(data, off, key_len)?).ok()?;
        off += key_len;
        let schema = if flags & F_SCHEMA != 0 {
            let schema = span_of(data, off, schema_len)?;
            off += schema_len;
            Some(schema)
        } else {
            None
        };
        let payload = span_of(data, off, payload_len)?;
        off += payload_len;
        let attachment = if flags & F_ATTACHMENT != 0 {
            Some(span_of(data, off, attachment_len)?)
        } else {
            None
        };
        #[cfg(feature = "transport-shm")]
        let payload = shared.map_or(payload, wz_session_core::extshm::ShmSendHandle::bytes);
        Some(Held {
            keyexpr,
            bytes: payload,
            source_info,
            timestamp,
            kind: if flags & F_DEL != 0 {
                SampleKind::Del
            } else {
                SampleKind::Put
            },
            encoding: (flags & F_ENCODING != 0).then(|| EncodingRef {
                packed_id: read_u32(data, at + R_ENCODING),
                schema,
            }),
            attachment,
            #[cfg(feature = "transport-shm")]
            shared,
        })
    }
}
