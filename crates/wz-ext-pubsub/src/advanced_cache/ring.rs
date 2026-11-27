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
//! session reads one state, and a span the session zeroed at its open is an empty ring. The state
//! and each record's header are read as arrays of their own length, taken once, so a field read at
//! one of the constant offsets below needs no check of its own, and a record whose header does not
//! lie whole in the span is no record: nothing here reads past the span whatever it holds.

use wz_session_core::sample::{EncodingRef, SampleKind, SourceInfo, TimestampHint};
#[cfg(feature = "advanced-recovery")]
use wz_session_core::{reliability::Reliability, sample::QosLevel, sink::SampleView};

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
#[cfg(feature = "advanced-recovery")]
const R_QOS: usize = 82;

// What a record's flags say it holds.
const F_DEL: u32 = 1;
const F_SOURCE: u32 = 1 << 1;
const F_ENCODING: u32 = 1 << 2;
const F_SCHEMA: u32 = 1 << 3;
const F_ATTACHMENT: u32 = 1 << 4;
#[cfg(feature = "transport-shm")]
const F_SHARED: u32 = 1 << 5;
const F_STAMPED: u32 = 1 << 6;
#[cfg(feature = "advanced-recovery")]
const F_QOS: u32 = 1 << 7;
#[cfg(feature = "advanced-recovery")]
const F_BEST_EFFORT: u32 = 1 << 8;

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

/// The ring's state, the first bytes of its span.
type RingHead = [u8; RING_HEAD_BYTES];

/// A record's header, the first bytes of the record.
type RecordHead = [u8; RECORD_HEAD_BYTES];

/// The word at `at` of a header. Every offset a caller passes is one of the constants above and
/// the header's length is its type's, so where this is inlined the place's check is folded away.
#[inline(always)]
fn head_u32<const N: usize>(head: &[u8; N], at: usize) -> u32 {
    head.get(at..)
        .and_then(<[u8]>::first_chunk::<4>)
        .map_or(0, |word| u32::from_ne_bytes(*word))
}

/// Write `value` as the word at `at` of a header, as [`head_u32`] reads it.
#[inline(always)]
fn set_head_u32<const N: usize>(head: &mut [u8; N], at: usize, value: u32) {
    if let Some(word) = head.get_mut(at..).and_then(<[u8]>::first_chunk_mut::<4>) {
        *word = value.to_ne_bytes();
    }
}

/// The double word at `at` of a record's header, as [`head_u32`] reads a word.
#[inline(always)]
fn head_u64(head: &RecordHead, at: usize) -> u64 {
    head.get(at..)
        .and_then(<[u8]>::first_chunk::<8>)
        .map_or(0, |word| u64::from_ne_bytes(*word))
}

/// Write `value` as the double word at `at` of a record's header.
#[inline(always)]
fn set_head_u64(head: &mut RecordHead, at: usize, value: u64) {
    if let Some(word) = head.get_mut(at..).and_then(<[u8]>::first_chunk_mut::<8>) {
        *word = value.to_ne_bytes();
    }
}

/// The header of the record at `at`; `None` where it does not lie whole in `data`, which no
/// record the ring wrote is.
fn record_head(data: &[u8], at: usize) -> Option<&RecordHead> {
    data.get(at..)?.first_chunk::<RECORD_HEAD_BYTES>()
}

/// The header of the record at `at`, to write; `None` as for [`record_head`].
fn record_head_mut(data: &mut [u8], at: usize) -> Option<&mut RecordHead> {
    data.get_mut(at..)?.first_chunk_mut::<RECORD_HEAD_BYTES>()
}

/// The word `field` of the header of the record at `at`; zero where the header does not lie
/// whole in `data`.
fn record_u32(data: &[u8], at: usize, field: usize) -> u32 {
    record_head(data, at).map_or(0, |head| head_u32(head, field))
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

/// What a record keeps of its sample beside the body: the stamps a cache answers with, and what
/// a subscriber hands on with a sample it held.
struct Stamps<'a> {
    source_info: Option<SourceInfo>,
    timestamp: Option<&'a TimestampHint>,
    #[cfg(feature = "advanced-recovery")]
    qos: Option<QosLevel>,
    #[cfg(feature = "advanced-recovery")]
    reliability: Reliability,
}

/// A session's ring, read and written over the bytes of its span.
pub(crate) struct RecordRing<'a> {
    /// The ring's state.
    head: &'a mut RingHead,
    /// The records.
    data: &'a mut [u8],
}

impl<'a> RecordRing<'a> {
    /// The ring `span` holds, or `None` for a span too short for one record of no sample, or not
    /// laid on the records' alignment.
    pub(crate) fn over(span: &'a mut [u8]) -> Option<Self> {
        if span.as_ptr() as usize % ALIGN != 0 || capacity(span.len()) < RECORD_HEAD_BYTES {
            return None;
        }
        let records = capacity(span.len());
        let (head, rest) = span.split_first_chunk_mut::<RING_HEAD_BYTES>()?;
        let data = rest.get_mut(..records)?;
        Some(Self { head, data })
    }

    /// The bytes of records the ring holds.
    pub(super) fn capacity(&self) -> usize {
        self.data.len()
    }

    fn state(&self, at: usize) -> usize {
        head_u32(self.head, at) as usize
    }

    fn set_state(&mut self, at: usize, value: usize) {
        set_head_u32(self.head, at, word(value));
    }

    /// A new cache's owner id: one no record in the ring carries, never the dead one.
    pub(super) fn register(&mut self) -> u32 {
        let mut owner = head_u32(self.head, NEXT_OWNER);
        loop {
            owner = owner.wrapping_add(1);
            if owner != DEAD && self.live(owner) == 0 {
                break;
            }
        }
        set_head_u32(self.head, NEXT_OWNER, owner);
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
            let total = record_u32(self.data, at, R_TOTAL) as usize;
            if total == 0 {
                return;
            }
            at = at.saturating_add(total);
        }
    }

    /// How many records of `owner` the ring holds.
    pub(crate) fn live(&self, owner: u32) -> usize {
        let mut live = 0usize;
        self.each_record(&mut |at| {
            if record_u32(self.data, at, R_OWNER) == owner {
                live = live.saturating_add(1);
            }
        });
        live
    }

    /// The offset of `owner`'s oldest record.
    fn oldest_of(&self, owner: u32) -> Option<usize> {
        let mut oldest = None;
        self.each_record(&mut |at| {
            if oldest.is_none() && record_u32(self.data, at, R_OWNER) == owner {
                oldest = Some(at);
            }
        });
        oldest
    }

    /// Mark the record at `at` dead, letting go of what it held: its bytes come back when the
    /// tail reaches it.
    fn kill(&mut self, at: usize) {
        let Some(head) = record_head(self.data, at) else {
            return;
        };
        if head_u32(head, R_OWNER) == DEAD {
            return;
        }
        #[cfg(feature = "transport-shm")]
        if head_u32(head, R_FLAGS) & F_SHARED != 0 {
            // SAFETY: a live record that says it holds a handle holds one, written by `write` at
            // this place, and dropping it here is the only drop it gets: the record is marked
            // dead next and read no more.
            unsafe {
                core::ptr::drop_in_place(self.shared_at(at));
            }
        }
        if let Some(head) = record_head_mut(self.data, at) {
            set_head_u32(head, R_OWNER, DEAD);
        }
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
        let total = record_u32(self.data, tail, R_TOTAL) as usize;
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
            let total = record_u32(self.data, at, R_TOTAL) as usize;
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
        let stamps = Stamps {
            source_info,
            timestamp: Some(timestamp),
            #[cfg(feature = "advanced-recovery")]
            qos: None,
            #[cfg(feature = "advanced-recovery")]
            reliability: Reliability::default(),
        };
        self.write(at, need, owner, body, &stamps);
    }

    /// Write the record at `at`, of `total` bytes.
    fn write(
        &mut self,
        at: usize,
        total: usize,
        owner: u32,
        body: SampleBody<'_>,
        stamps: &Stamps<'_>,
    ) {
        let source_info = stamps.source_info.as_ref();
        let schema = body.encoding.and_then(|encoding| encoding.schema);
        let mut flags = 0;
        if matches!(body.kind, SampleKind::Del) {
            flags |= F_DEL;
        }
        if source_info.is_some() {
            flags |= F_SOURCE;
        }
        if stamps.timestamp.is_some() {
            flags |= F_STAMPED;
        }
        #[cfg(feature = "advanced-recovery")]
        if stamps.qos.is_some() {
            flags |= F_QOS;
        }
        #[cfg(feature = "advanced-recovery")]
        if matches!(stamps.reliability, Reliability::BestEffort) {
            flags |= F_BEST_EFFORT;
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
        let ts_zid = stamps.timestamp.map_or(&[][..], TimestampHint::zid_prefix);
        let si_zid = source_info.map_or(&[][..], SourceInfo::zid_prefix);
        // The room the ring took holds the record whole, so its header lies in the span.
        let Some(head) = record_head_mut(self.data, at) else {
            return;
        };
        set_head_u32(head, R_TOTAL, word(total));
        set_head_u32(head, R_OWNER, owner);
        set_head_u32(head, R_FLAGS, flags);
        set_head_u32(head, R_KEY, word(body.keyexpr.len()));
        set_head_u32(head, R_PAYLOAD, word(body.payload.len()));
        set_head_u32(
            head,
            R_ATTACHMENT,
            word(body.attachment.map_or(0, <[u8]>::len)),
        );
        set_head_u32(
            head,
            R_ENCODING,
            body.encoding.map_or(0, |encoding| encoding.packed_id),
        );
        set_head_u32(head, R_SCHEMA, word(schema.map_or(0, <[u8]>::len)));
        set_head_u64(head, R_TIME, stamps.timestamp.map_or(0, |ts| ts.time));
        put_bytes(head, R_TS_ZID, ts_zid);
        put_bytes(head, R_SI_ZID, si_zid);
        set_head_u32(head, R_EID, source_info.map_or(0, |si| si.eid));
        set_head_u32(head, R_SN, source_info.map_or(0, |si| si.sn));
        head[R_TS_ZID_LEN] = ts_zid.len() as u8;
        head[R_SI_ZID_LEN] = si_zid.len() as u8;
        #[cfg(feature = "advanced-recovery")]
        {
            head[R_QOS] = stamps.qos.map_or(0, |qos| qos.raw);
        }
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

    /// The owner of the record at `at`.
    #[cfg(feature = "advanced-recovery")]
    fn owner_at(&self, at: usize) -> u32 {
        record_u32(self.data, at, R_OWNER)
    }

    /// The number `order` reads off the record at `at`.
    #[cfg(feature = "advanced-recovery")]
    fn key_at(&self, at: usize, order: Order) -> u64 {
        match order {
            Order::Sn => u64::from(record_u32(self.data, at, R_SN)),
            #[cfg(feature = "advanced-history")]
            Order::Time => record_head(self.data, at).map_or(0, |head| head_u64(head, R_TIME)),
        }
    }

    /// The record of `owner` held under `key`, read in `order`.
    #[cfg(feature = "advanced-recovery")]
    pub(crate) fn find(&self, owner: u32, order: Order, key: u64) -> Option<usize> {
        let mut found = None;
        self.each_record(&mut |at| {
            if found.is_none() && self.owner_at(at) == owner && self.key_at(at, order) == key {
                found = Some(at);
            }
        });
        found
    }

    /// The record of `owner` held under the least key read in `order`, with its key.
    #[cfg(feature = "advanced-recovery")]
    pub(crate) fn first(&self, owner: u32, order: Order) -> Option<(u64, usize)> {
        let mut first: Option<(u64, usize)> = None;
        self.each_record(&mut |at| {
            if self.owner_at(at) == owner {
                let key = self.key_at(at, order);
                if first.is_none_or(|(least, _)| key < least) {
                    first = Some((key, at));
                }
            }
        });
        first
    }

    /// Keep the sample `view` reads as a record of `owner`, with every stamp a subscriber hands
    /// on with it. Unlike [`Self::keep`], no live record is let go for room: the dead ones at the
    /// ring's tail are taken back, and a sample that finds no room after them is not kept, which
    /// the answer says.
    #[cfg(feature = "advanced-recovery")]
    pub(crate) fn place(&mut self, owner: u32, view: &dyn SampleView) -> bool {
        let body = SampleBody {
            keyexpr: view.keyexpr(),
            payload: view.payload(),
            kind: view.kind(),
            encoding: view.encoding().map(EncodingRef::of).or_else(|| {
                view.encoding_parts()
                    .map(|(packed_id, schema)| EncodingRef { packed_id, schema })
            }),
            attachment: view
                .attachment()
                .or_else(|| view.attachment_shared().map(|bytes| &**bytes)),
            #[cfg(feature = "transport-shm")]
            shared: None,
        };
        let timestamp = view.timestamp().cloned().or_else(|| {
            view.timestamp_parts()
                .and_then(|(time, zid)| TimestampHint::new(time, zid))
        });
        let stamps = Stamps {
            source_info: view.source_info().cloned(),
            timestamp: timestamp.as_ref(),
            qos: view.qos(),
            reliability: view.reliability(),
        };
        let Some(need) = record_bytes(&body).filter(|need| *need <= self.capacity()) else {
            return false;
        };
        loop {
            if let Some(at) = self.take_room(need) {
                self.write(at, need, owner, body, &stamps);
                return true;
            }
            if self.state(COUNT) == 0 || self.owner_at(self.state(TAIL)) != DEAD {
                return false;
            }
            self.pop_tail();
        }
    }

    /// The sample of the record at `at`, read where it lies, as a subscriber hands it on.
    #[cfg(feature = "advanced-recovery")]
    pub(crate) fn view_at(&self, at: usize) -> Option<RecordView<'_>> {
        let head = record_head(self.data, at)?;
        let flags = head_u32(head, R_FLAGS);
        let qos = (flags & F_QOS != 0).then(|| QosLevel::from_raw(head[R_QOS]));
        Some(RecordView {
            held: self.held(at)?,
            qos,
            reliability: if flags & F_BEST_EFFORT != 0 {
                Reliability::BestEffort
            } else {
                Reliability::Reliable
            },
        })
    }

    /// Let the record at `at` go, and take back the bytes of the dead records at the ring's tail.
    #[cfg(feature = "advanced-recovery")]
    pub(crate) fn let_go(&mut self, at: usize) {
        self.kill(at);
        self.take_back();
    }

    /// Let every record of `owner` go, and take back what the ring's tail then holds dead.
    #[cfg(feature = "advanced-retention")]
    pub(crate) fn let_go_all(&mut self, owner: u32) {
        self.forget(owner);
        self.take_back();
    }

    /// Take back the bytes of the dead records at the ring's tail.
    #[cfg(feature = "advanced-recovery")]
    fn take_back(&mut self) {
        while self.state(COUNT) != 0 && self.owner_at(self.state(TAIL)) == DEAD {
            self.pop_tail();
        }
    }

    /// Call `each` with every live sample of `owner`, oldest first.
    pub(super) fn each_of(&self, owner: u32, each: &mut dyn FnMut(Held<'_>)) {
        self.each_record(&mut |at| {
            if record_u32(self.data, at, R_OWNER) == owner {
                if let Some(held) = self.held(at) {
                    each(held);
                }
            }
        });
    }

    /// The sample of the record at `at`, read where it lies.
    fn held(&self, at: usize) -> Option<Held<'_>> {
        let data: &[u8] = self.data;
        let head = record_head(data, at)?;
        let flags = head_u32(head, R_FLAGS);
        let key_len = head_u32(head, R_KEY) as usize;
        let payload_len = head_u32(head, R_PAYLOAD) as usize;
        let attachment_len = head_u32(head, R_ATTACHMENT) as usize;
        let schema_len = head_u32(head, R_SCHEMA) as usize;
        let ts_zid_len = usize::from(head[R_TS_ZID_LEN]);
        let si_zid_len = usize::from(head[R_SI_ZID_LEN]);
        let timestamp = if flags & F_STAMPED != 0 {
            Some(TimestampHint::new(
                head_u64(head, R_TIME),
                span_of(head, R_TS_ZID, ts_zid_len)?,
            )?)
        } else {
            None
        };
        let source_info = if flags & F_SOURCE != 0 {
            Some(SourceInfo::new(
                span_of(head, R_SI_ZID, si_zid_len)?,
                head_u32(head, R_EID),
                head_u32(head, R_SN),
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
                packed_id: head_u32(head, R_ENCODING),
                schema,
            }),
            attachment,
            #[cfg(feature = "transport-shm")]
            shared,
        })
    }
}

/// Which number of its records orders what one owner holds: a sample's sequence number, or its
/// timestamp's time.
#[cfg(feature = "advanced-recovery")]
#[derive(Clone, Copy)]
pub(crate) enum Order {
    Sn,
    #[cfg(feature = "advanced-history")]
    Time,
}

/// A held sample as a subscriber hands it on, read where its record lies.
#[cfg(feature = "advanced-recovery")]
pub(crate) struct RecordView<'a> {
    held: Held<'a>,
    qos: Option<QosLevel>,
    reliability: Reliability,
}

#[cfg(feature = "advanced-recovery")]
impl SampleView for RecordView<'_> {
    fn keyexpr(&self) -> &str {
        self.held.keyexpr
    }
    fn payload(&self) -> &[u8] {
        self.held.bytes
    }
    fn kind(&self) -> SampleKind {
        self.held.kind
    }
    fn reliability(&self) -> Reliability {
        self.reliability
    }
    fn qos(&self) -> Option<QosLevel> {
        self.qos
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.held.attachment
    }
    fn timestamp(&self) -> Option<&TimestampHint> {
        self.held.timestamp.as_ref()
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.held.source_info.as_ref()
    }
    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        self.held
            .encoding
            .as_ref()
            .map(|encoding| (encoding.packed_id, encoding.schema))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed span of `len` bytes laid on a record's alignment: an empty ring's.
    fn words(len: usize) -> Vec<u64> {
        vec![0u64; len / 8]
    }

    /// The bytes of `words`.
    fn bytes(words: &mut [u64]) -> &mut [u8] {
        let len = words.len() * 8;
        // SAFETY: the words are borrowed mutably for as long as the bytes are, and any bytes are a
        // valid `u8`.
        unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), len) }
    }

    /// The ring's state is the first bytes of its span, each field the word at its offset, so a
    /// span the session zeroed is an empty ring. Turned red by a state taken from anywhere but
    /// the span's start (`RecordRing::over`), or a field read at another place than it is written.
    #[test]
    fn the_rings_state_is_the_first_words_of_its_span() {
        let mut span = words(RING_HEAD_BYTES + 256);
        {
            let mut ring = RecordRing::over(bytes(&mut span)).expect("a span of whole records");
            for (field, value) in [(TAIL, 8), (HEAD, 96), (END, 200), (COUNT, 3), (WRAPPED, 1)] {
                ring.set_state(field, value);
                assert_eq!(ring.state(field), value);
            }
        }
        let raw = bytes(&mut span);
        for (field, value) in [
            (TAIL, 8u32),
            (HEAD, 96),
            (END, 200),
            (COUNT, 3),
            (WRAPPED, 1),
        ] {
            assert_eq!(
                raw[field..field + 4],
                value.to_ne_bytes(),
                "the word at {field}"
            );
        }
    }

    /// A record whose header does not lie whole in the span is no record, however its first words
    /// read: it has no owner, holds no sample and is let go of without a write. Turned red by a
    /// header read field by field (`record_head`), which would read the owner of the words that
    /// do lie in the span.
    #[test]
    fn a_record_whose_header_runs_past_the_span_is_no_record() {
        let mut span = words(RING_HEAD_BYTES + 256);
        let mut ring = RecordRing::over(bytes(&mut span)).expect("a span of whole records");
        let capacity = ring.capacity();
        let at = capacity - 8;
        ring.set_state(TAIL, at);
        ring.set_state(HEAD, capacity);
        ring.set_state(COUNT, 1);
        ring.data[at + R_TOTAL..at + R_TOTAL + 4].copy_from_slice(&8u32.to_ne_bytes());
        ring.data[at + R_OWNER..at + R_OWNER + 4].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(ring.live(7), 0);
        assert!(ring.held(at).is_none());
        ring.forget(7);
        assert_eq!(
            ring.data[at + R_OWNER..at + R_OWNER + 4],
            7u32.to_ne_bytes(),
            "nothing was written for it"
        );
    }

    /// A record the ring writes reads back field by field through its header: its owner, its
    /// lengths, its stamps and its key. Turned red by a field written at one offset and read at
    /// another, or a header taken at another place than the record's.
    #[test]
    fn a_kept_record_reads_back_through_its_header() {
        let mut span = words(RING_HEAD_BYTES + 512);
        let mut ring = RecordRing::over(bytes(&mut span)).expect("a span of whole records");
        let owner = ring.register();
        let zid = [0xA5u8; 16];
        let stamp = TimestampHint::new(0x1234_5678_9ABC_DEF0, &zid).expect("a stamp of a zid");
        let body = SampleBody {
            keyexpr: "demo/ring",
            payload: b"payload",
            kind: SampleKind::Put,
            encoding: None,
            attachment: Some(b"att"),
            #[cfg(feature = "transport-shm")]
            shared: None,
        };
        ring.keep(owner, 4, body, Some(SourceInfo::new(&zid, 9, 41)), &stamp);
        assert_eq!(ring.live(owner), 1);
        let mut seen = 0;
        ring.each_of(owner, &mut |held| {
            seen += 1;
            assert_eq!(held.keyexpr, "demo/ring");
            assert_eq!(held.bytes, b"payload");
            assert_eq!(held.attachment, Some(&b"att"[..]));
            assert_eq!(held.timestamp.as_ref().map(|ts| ts.time), Some(stamp.time));
            let source = held
                .source_info
                .as_ref()
                .expect("the record keeps its source");
            assert_eq!((source.eid, source.sn), (9, 41));
            assert!(held.encoding.is_none());
        });
        assert_eq!(seen, 1);
    }
}
