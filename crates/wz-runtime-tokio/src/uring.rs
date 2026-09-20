// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y589 — `runtime-tokio-uring`: ARCHITECTURE §9.5 row 3.
//!
//! The §9.5 table's claim is that ONE pool lifecycle FSM serves every platform
//! and only the EDGE ACTIONS differ. Row 1 arms a DMA controller; row 2 waits on
//! `epoll` and copies; row 3 hands the kernel a registered `iovec` and submits
//! `IORING_OP_READ_FIXED`. Until this module the table had one incarnation, so
//! the claim was an assertion about code that did not exist.
//!
//! [`crate::zero_copy`] built row 2's pool consumer. This is row 3's, and the
//! buffers registered with the kernel here are literally a generated pool's
//! slots rather than buffers of this module's own — which is why
//! `runtime-tokio-uring` implies `runtime-zero-copy` rather than sitting beside
//! it.
//!
//! ⚠ WHICH pool changed in R2746, and this paragraph used to name
//! `reassembly_pool_ap`. It is `session_rx_pool_ap`, the LINK-RX table; the
//! section at the end of this header carries the argument. The implication on
//! `runtime-zero-copy` is unaffected, because the seam that makes a generated
//! pool reachable at all is still that feature's.
//!
//! ## What "zero-copy" means on this path, precisely
//!
//! Row 2 reads into a link buffer and the chain then stages a copy of it. Here
//! the kernel writes into the pool slot the FRAME already holds, and completion
//! only narrows the frame to what was written. There is no intermediate buffer,
//! which is the RFC's own definition of the RX happy path
//! (`docs/rfc-sce-protocol-synthesis.md` — "DMA fills pool slot → codec parses
//! in place"), with `io_uring` in the DMA controller's seat.
//!
//! ## Why `io-uring` and not `tokio-uring`
//!
//! `tokio-uring` brings its own current-thread runtime. wz already has a
//! multi-threaded one that every other driver in this crate is written against,
//! and two reactors contending for one session is a different feature from the
//! one the table describes. This crate is a thin binding to `io_uring_setup` and
//! the submission queue, so the adapter registers and submits from wz's own
//! runtime.
//!
//! ## What is NOT built here, stated so a later round does not misread it
//!
//! This is the ADAPTER the inventory atom names (`F=io_uring fixed-buf
//! adapter`), not a reactor swap. `TcpDriver`'s framing state machine still
//! reads through `tokio::io`; nothing selects this path for a production link
//! yet, and doing so needs the length-prefix sniff to become fixed-buffer aware.
//! The atom's status records that residual rather than leaving it to be
//! discovered.
//!
//! ## R2746 — the registration moved to the LINK-RX table, and that was a
//! ## GRANULARITY error rather than a preference
//!
//! Until this round the ring registered `reassembly_pool_ap` and
//! [`FixedSlotRing::read_fixed_into`] appended into a reassembly CHAIN. A chain
//! accumulates one message's fragment payloads and which chain a payload
//! belongs to is knowable only after the frame carrying it has been DECODED —
//! so at the moment the kernel needs a destination, no chain has been chosen.
//! What comes off a socket is a FRAME.
//!
//! `crate::link_rx_pool`'s own header had already written down why the adapter
//! was pointed there anyway: "it is the reason `crate::uring`'s
//! `read_fixed_into` reads into a chain slot today: there was no link-RX pool
//! on this profile to read into". R2739 built that pool, R2740 the arena over
//! it, and R2742 put both production stream link reads on it. The reason the
//! adapter aimed at the wrong table is therefore gone, and this round moves it.
//!
//! Two things follow that are not cosmetic:
//!
//! * the pinned requirement falls from 32 slots x 1 MiB to 64 x 65600 — the
//!   adapter was charging `RLIMIT_MEMLOCK` for eight times the memory a link
//!   read can use, and a host that could have run it was told it could not;
//! * the destination is now the table a production frame read already lands
//!   in, which is what the atom's first residual has to aim at before anything
//!   can select this path.

use std::io;
use std::os::fd::RawFd;

use io_uring::{opcode, types, IoUring};

use crate::frame_arena::FrameArena;
use crate::link_rx_arena::{LinkRxArena, LinkRxFrame};
use crate::session_rx_pool_ap::{SLOT_COUNT, SLOT_SIZE};

/// An `io_uring` instance whose registered fixed buffers ARE a pool's slots.
///
/// The registration is what makes `IORING_OP_READ_FIXED` legal: the kernel pins
/// the pages once, at registration, so each read costs no per-call
/// `get_user_pages`. That is the resource discipline §9.5 names for this row
/// ("io_uring fixed-buffer registration count") in place of the MCU rows'
/// no-alloc rule.
pub struct FixedSlotRing {
    ring: IoUring,
    registered: usize,
}

impl FixedSlotRing {
    /// Build a ring and register every slot of the LINK-RX table as a fixed
    /// buffer, PLACED AT ITS OWN SLOT INDEX — so a slot index IS its
    /// `buf_index` and the two never need a mapping table to drift out of.
    ///
    /// R2746 — "placed at its own index" replaces "appended in acquisition
    /// order", and the claim for it is DEFENSIVE rather than corrective. The
    /// first draft of this comment said acquisition order would misbind a
    /// recycled table; that was measured and is FALSE for this pool.
    /// `SessionRxPoolAp::reserve` hands out the first FREE slot rather than
    /// popping a freelist, so acquisition order IS index order however the
    /// table has been used — churning it and printing the drain order gives
    /// `[0, 1, 2, ...]` every time, and reverting this derivation leaves every
    /// test in this module green.
    ///
    /// What the derivation buys is that the binding no longer DEPENDS on that.
    /// The index-order discipline is a property of the emitted pool, not a
    /// contract anything states; an emit that recycled slots would misbind
    /// every read, silently, and [`LinkRxArena::slot_of`] — the table's own
    /// address-to-index oracle — makes that impossible rather than unlikely.
    /// ⚠ It is therefore UNWITNESSED, which the test module records at length
    /// so the next round does not mistake it for tested.
    ///
    /// # Safety contract, upheld by the signature
    ///
    /// Registered buffers must stay at their addresses until the ring is
    /// dropped. The table lives in a `Box` behind an `Arc` the arena holds, so
    /// the storage does not move when the arena does; taking `&mut LinkRxArena`
    /// for the call and returning an owned ring does NOT by itself pin the
    /// arena, so the caller must keep it alive — which
    /// [`Self::read_fixed_into`] cannot check and the tests below therefore
    /// state explicitly by scoping both together.
    pub fn register(arena: &mut LinkRxArena, entries: u32) -> io::Result<Self> {
        let ring = IoUring::new(entries)?;

        // Take every slot, record each one AT ITS INDEX, then drop the frames
        // so the table is whole again. `take` is the arena's only way to reach
        // a slot, which is the point: the addresses come from the same seam a
        // production read uses rather than from the pool's private storage.
        let mut iovecs: Vec<libc::iovec> = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            };
            SLOT_COUNT
        ];
        let mut held: Vec<LinkRxFrame> = Vec::with_capacity(SLOT_COUNT);
        let mut registered = 0usize;
        for _ in 0..SLOT_COUNT {
            let mut frame = arena.take(SLOT_SIZE);
            if !frame.is_pooled() {
                // The table ran dry, so this frame is an allocation and is not
                // part of the registration. Stop rather than register it: a
                // spilled address is not in the pinned region and a `buf_index`
                // for it would name someone else's slot.
                break;
            }
            let base = frame.as_mut().as_mut_ptr();
            let Some(idx) = arena.slot_of(base) else {
                // A pooled frame whose address the table does not recognise is
                // a contradiction, not a slot to skip.
                return Err(io::Error::other(
                    "a pooled frame's address is not in its own table",
                ));
            };
            iovecs[idx] = libc::iovec {
                iov_base: base as *mut libc::c_void,
                iov_len: SLOT_SIZE,
            };
            registered += 1;
            held.push(frame);
        }
        // A partial registration would leave holes the kernel reads as null
        // iovecs, and `EFAULT` on those reads looks like a bad fd. Refuse it
        // with the count instead.
        if registered != SLOT_COUNT {
            drop(held);
            return Err(io::Error::other(format!(
                "the link-RX table yielded {registered} of {SLOT_COUNT} slots; \
                 a partial registration binds buf_index to the wrong slot"
            )));
        }

        // Register BEFORE returning the slots: the pointers are valid either
        // way (the storage belongs to the table, not to the frame), but holding
        // them across the call is what makes "every slot, at its index" true
        // rather than a race with another taker.
        //
        // SAFETY: each iovec points at one `[u8; SLOT_SIZE]` inside the table's
        // boxed storage, which outlives this call and — per the type-level
        // contract above — the ring.
        let result = unsafe { ring.submitter().register_buffers(&iovecs) };
        drop(held);
        result
            .map_err(|e| registration_error(e, Self::required_locked_bytes(), memlock_limit()))?;

        Ok(Self { ring, registered })
    }

    /// Bytes [`Self::register`] asks the kernel to PIN: every pool slot, whole.
    ///
    /// R311y593. This is not an internal detail. `IORING_REGISTER_BUFFERS` pins
    /// the pages at registration — that is the whole point of the row, no
    /// per-call `get_user_pages` — and pinned pages are charged to
    /// `RLIMIT_MEMLOCK`. So the adapter carries a DEPLOYMENT requirement that
    /// scales with the pool the SCXML declares, and a host whose limit is below
    /// it cannot register at all. Stating it as a constant lets a caller check
    /// before trying, lets the failure path name the shortfall, and moves with
    /// the pool dims instead of being a number written down twice.
    pub const fn required_locked_bytes() -> usize {
        SLOT_COUNT * SLOT_SIZE
    }

    /// How many pool slots are registered with the kernel.
    ///
    /// Observability, and the one number that distinguishes "the registration
    /// ran" from "the registration ran and registered nothing" — a ring with
    /// zero buffers accepts `register_buffers` and then fails every read with
    /// `EFAULT`, which reads like a bad fd.
    pub fn registered(&self) -> usize {
        self.registered
    }

    /// `IORING_OP_READ_FIXED` from `fd` straight into `frame`'s LINK-RX slot,
    /// at most `len` bytes and never past the slot. Returns what the kernel
    /// wrote and NARROWS the frame to it.
    ///
    /// R2746 — the destination is a frame rather than a reassembly chain, which
    /// is the granularity correction the module header argues. A frame is what
    /// a socket read lands, and `arena.take(want)` is how a production framing
    /// read already gets one.
    ///
    /// The signature takes the arena and the frame rather than a bare index,
    /// and that is a correctness fix rather than ergonomics. The first version
    /// took `(fd, buf_index, len)` and passed a null `addr`, on the reading that
    /// `buf_index` alone tells the kernel where to write. It does not:
    /// `READ_FIXED`'s `addr` is the ACTUAL destination and must lie inside the
    /// registered region that `buf_index` names — a null one is `EFAULT`, which
    /// is what the test reported. Deriving BOTH the address and the index from
    /// the frame makes the only expressible target the right one, and makes
    /// them one derivation rather than two things to keep in step.
    ///
    /// A SPILLED frame is REFUSED rather than read into. Its bytes are an
    /// allocation the kernel was never given, so no `buf_index` names them; a
    /// read there would either fault or land in whichever slot that index
    /// happens to hold. The caller's fallback is the ordinary read path, which
    /// is what `is_pooled` is for.
    ///
    /// Blocking on the completion rather than returning a future: this is the
    /// adapter, and how a session's link drives it alongside the tokio reactor
    /// is the residual the module docs name. A future here would imply an
    /// integration that does not exist.
    pub fn read_fixed_into(
        &mut self,
        fd: RawFd,
        arena: &LinkRxArena,
        frame: &mut LinkRxFrame,
        len: usize,
    ) -> io::Result<usize> {
        if !frame.is_pooled() {
            return Err(io::Error::other(
                "a spilled frame is not in the registration; read it the ordinary way",
            ));
        }
        let dst = frame.as_mut().as_mut_ptr();
        let buf_index = arena
            .slot_of(dst)
            .ok_or_else(|| io::Error::other("this frame's slot is not in the arena's table"))?;
        if buf_index >= self.registered {
            return Err(io::Error::other(format!(
                "buf_index {buf_index} is not a registered slot ({} registered)",
                self.registered
            )));
        }
        // Never let the kernel write past the frame's own width: `take(want)`
        // reserved `want` bytes and the accessors read exactly that many, so a
        // completion larger than it would leave bytes nobody can see.
        let len = len.min(frame.as_ref().len());
        if len == 0 {
            return Ok(0);
        }

        let entry = opcode::ReadFixed::new(types::Fd(fd), dst, len as u32, buf_index as u16)
            .offset(u64::MAX) // -1: read at the file's current position
            .build()
            .user_data(buf_index as u64);

        // SAFETY: `dst` is the first byte of the registered region named by
        // `buf_index`, with `len` bytes of room proven above; the fd is the
        // caller's and the queue is not shared, so nothing else is mid-push.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "io_uring SQ full"))?;
        }
        self.ring.submit_and_wait(1)?;

        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::other("io_uring reported no completion after wait"))?;
        let res = cqe.result();
        if res < 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }
        let n = res as usize;
        if n > len {
            // The kernel cannot report more than it was asked for, and if it
            // ever did the extra bytes are already written. Say so rather than
            // narrowing to a number that would hide it.
            return Err(io::Error::other(format!(
                "io_uring reported {n} bytes for a {len}-byte read"
            )));
        }
        // The frame is now exactly what was filled. `take(want)` gave it `want`
        // bytes of room and a short read means the frame is narrower than the
        // room; without this the reader downstream would see whatever the slot
        // held before, inside a frame claiming to be `want` wide.
        frame.truncate(n);
        Ok(n)
    }
}

/// The process's `RLIMIT_MEMLOCK` as `(soft, hard)`.
///
/// `None` when the query itself failed — reported as an absence rather than as
/// a zero, because "we could not read the limit" and "the limit is nothing"
/// send a reader to different places.
fn memlock_limit() -> Option<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` only writes the struct it is handed, which is fully
    // initialised above and lives for the call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    // No casts: `rlim_t` IS `u64` on every target that has `io_uring`, and a
    // cast that is a no-op today is a cast nobody re-checks when it stops being
    // one.
    (rc == 0).then_some((lim.rlim_cur, lim.rlim_max))
}

/// Turn a fixed-buffer registration failure into one a reader can act on.
///
/// R311y593. `register_buffers` reports a memlock shortfall as a bare `ENOMEM`,
/// which `io::Error` renders as "Cannot allocate memory" — a message that reads
/// like the process is out of heap and sends the reader to look for a leak.
/// That cost a hosted CI round exactly this way: the lane was green on a
/// workstation whose limit is 3.9 GiB and red on a runner whose limit is 8 MiB,
/// against a pool that needs 32 MiB, and the error named none of the three
/// numbers.
///
/// Pure in `(err, needed, limit)` so the message is testable without a syscall
/// and without mutating a process-global limit — lowering `RLIMIT_MEMLOCK` to
/// provoke the real error would race every other test in the binary.
///
/// Any errno OTHER than `ENOMEM` passes through untouched. This maps one
/// specific confusion; dressing an `EINVAL` up as a memlock problem would
/// manufacture a second one.
fn registration_error(err: io::Error, needed: usize, limit: Option<(u64, u64)>) -> io::Error {
    if err.raw_os_error() != Some(libc::ENOMEM) {
        return err;
    }
    let measured = match limit {
        Some((soft, hard)) => format!("RLIMIT_MEMLOCK is soft={soft} hard={hard} bytes"),
        None => String::from("RLIMIT_MEMLOCK could not be read"),
    };
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!(
            "io_uring fixed-buffer registration needs {needed} bytes of LOCKABLE \
             memory ({SLOT_COUNT} pool slots x {SLOT_SIZE} bytes, pinned at \
             registration) and the kernel refused with ENOMEM; {measured}. This \
             is a limit, not heap exhaustion: raise RLIMIT_MEMLOCK (ulimit -l, \
             or LimitMEMLOCK= under systemd) to at least {needed} bytes."
        ),
    )
}

/// R311y593 — ⚠ the registering tests below want `--test-threads=1`.
///
/// Each one pins the WHOLE pool ([`FixedSlotRing::required_locked_bytes`]), so
/// two running concurrently ask the kernel for twice it and the second is
/// refused with ENOMEM. On a host whose `RLIMIT_MEMLOCK` is gigabytes that never
/// shows; on one provisioned to exactly one registration's worth it is
/// immediate. Layer C1br serializes them for this reason — a bare
/// `cargo test -p wz-runtime-tokio --features runtime-tokio-uring` on a
/// tightly-limited box can fail here without anything being wrong with the
/// adapter.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    /// Every LINK-RX slot is registered, and at its own index.
    ///
    /// The count separates "the registration ran" from "the registration ran
    /// and registered nothing" — a ring with zero buffers accepts
    /// `register_buffers` and then fails every read with `EFAULT`, which reads
    /// like a bad fd rather than like an empty registration.
    #[test]
    fn registration_covers_every_link_rx_slot() {
        let mut arena = LinkRxArena::new();
        let ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");
        assert_eq!(ring.registered(), SLOT_COUNT);
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "registration must hand every slot back"
        );
    }

    /// THE ROW-3 CLAIM: the kernel writes into the link-RX slot itself.
    ///
    /// Not "a read succeeded" — that would pass with an ordinary `READ` into a
    /// scratch buffer. The witness is the ADDRESS: the frame reports itself as
    /// pooled and the arena's own `slot_of` resolves its bytes to a slot index,
    /// so the only way the payload is readable through it is if
    /// `IORING_OP_READ_FIXED` landed in the registered region that IS that
    /// slot. Nothing in this test copies.
    #[test]
    fn the_kernel_writes_into_the_frames_own_link_rx_slot() {
        let mut arena = LinkRxArena::new();
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        let payload = b"read-fixed straight into the link-rx slot";
        let mut frame = arena.take(payload.len());
        assert!(frame.is_pooled(), "a fresh table must serve from a slot");
        let idx = arena
            .slot_of(frame.as_ref().as_ptr())
            .expect("a pooled frame resolves to its slot");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(payload).expect("write");
        drop(wr);

        let n = ring
            .read_fixed_into(rd.as_raw_fd(), &arena, &mut frame, payload.len())
            .expect("READ_FIXED");
        assert_eq!(n, payload.len());
        assert_eq!(
            arena.slot_of(frame.as_ref().as_ptr()),
            Some(idx),
            "the frame kept its slot"
        );
        assert_eq!(
            frame.as_ref(),
            payload,
            "the bytes must be readable through the POOL SLOT, not a copy"
        );

        // The slot is still the frame's, and the table says so.
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "the frame still holds its slot after the kernel wrote to it"
        );
        drop(rd);
        drop(frame);
        assert_eq!(arena.free_slots(), SLOT_COUNT);
    }

    // ⛔⛔ A TEST FOR THE INDEX DERIVATION STOOD HERE AND WAS REMOVED, because
    // it could not discriminate. Recorded rather than deleted quietly, so the
    // next round does not rebuild it.
    //
    // `register` places each slot's iovec at the index `slot_of` reports, where
    // it once appended in acquisition order. The test asserted that a read
    // lands in its own slot, and the control for it — reverting to acquisition
    // order — was run FOUR times and came back GREEN every time. Under this
    // tree's rule that is a finding, not a pass, and the finding was measured:
    //
    //   PRE-REGISTER DRAIN ORDER: [0, 1, 2, 3, 4, 5, 6, 7]
    //
    // printed after churning the table (four frames taken and released) to
    // permute it. `SessionRxPoolAp::reserve` does NOT keep a LIFO freelist of
    // recycled slots — it hands out the first FREE slot, so acquisition order
    // IS index order for this pool, always, and no arrangement of takes and
    // releases separates the two placements. Two guesses about the recycling
    // discipline were wrong before the measurement settled it.
    //
    // ⚠ THE DERIVATION STAYS, and its justification changes from "this fixes a
    // misbinding" — it does not, there is none to fix — to "this stops the
    // binding from depending on an allocator property nothing else guarantees".
    // `reserve`'s index-order discipline is emitted, not contracted; a future
    // emit that recycled slots would silently misbind every read, and
    // `slot_of` is what makes that impossible rather than merely unlikely.
    // The honest state is that the derivation is UNWITNESSED here and cheap,
    // which is a different thing from tested.
    /// A SHORT read narrows the frame to what was actually written.
    ///
    /// Without the narrowing the frame keeps the width `take` reserved and the
    /// reader downstream sees trailing bytes of whatever the slot held before —
    /// which on a recycled slot is another peer's frame. The slot is DIRTIED
    /// first precisely so a stale tail would be visible: on a fresh table the
    /// bytes are zero and a missing truncate reads as a harmless run of nulls.
    #[test]
    fn a_short_read_narrows_the_frame_to_what_the_kernel_wrote() {
        let mut arena = LinkRxArena::new();
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        // Dirty a slot, then return it so the next `take` may hand it back.
        {
            let mut dirty = arena.take(64);
            dirty.as_mut().fill(0xAB);
        }

        let payload = b"short";
        let room = 64;
        let mut frame = arena.take(room);
        assert!(frame.is_pooled());
        assert_eq!(frame.as_ref().len(), room, "the frame starts at its room");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(payload).expect("write");
        drop(wr);

        let n = ring
            .read_fixed_into(rd.as_raw_fd(), &arena, &mut frame, room)
            .expect("READ_FIXED");
        assert_eq!(n, payload.len());
        assert_eq!(
            frame.as_ref(),
            payload,
            "the frame must be exactly what was written, with no stale tail"
        );
        drop(rd);
    }

    /// A SPILLED frame is refused rather than read into.
    ///
    /// Its bytes are an allocation the kernel was never handed, so no
    /// `buf_index` names them; reading there would fault or land in whichever
    /// slot that index happens to hold. Driven through the real seam — a frame
    /// wider than a slot is the arena's own spill arm — rather than by
    /// constructing one, so the refusal is proven against the shape a caller
    /// can actually produce.
    #[test]
    fn a_spilled_frame_is_refused_because_it_is_not_in_the_registration() {
        let mut arena = LinkRxArena::new();
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        let mut frame = arena.take(SLOT_SIZE + 1);
        assert!(!frame.is_pooled(), "a frame wider than a slot must spill");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(b"x").expect("write");
        drop(wr);

        let err = ring
            .read_fixed_into(rd.as_raw_fd(), &arena, &mut frame, 1)
            .expect_err("a spilled frame has no registered slot");
        assert!(
            err.to_string().contains("spilled"),
            "the refusal must name the cause: {err}"
        );
        drop(rd);
    }

    /// R311y593 — a memlock shortfall must READ like one.
    ///
    /// The numbers are the whole value of the mapping: a reader who sees only
    /// "Cannot allocate memory" looks for a leak, and a reader who sees the
    /// requirement beside the measured limit runs `ulimit -l`. Asserting the
    /// three numbers rather than the prose keeps this from passing on a message
    /// that was reworded into saying nothing.
    #[test]
    fn a_memlock_shortfall_is_reported_as_a_limit_not_as_heap_exhaustion() {
        let mapped = registration_error(
            io::Error::from_raw_os_error(libc::ENOMEM),
            FixedSlotRing::required_locked_bytes(),
            Some((8 * 1024 * 1024, 8 * 1024 * 1024)),
        );
        let text = mapped.to_string();
        assert!(
            text.contains(&FixedSlotRing::required_locked_bytes().to_string()),
            "the requirement must be named: {text}"
        );
        assert!(
            text.contains("8388608"),
            "the MEASURED limit must be named: {text}"
        );
        assert!(
            text.contains("RLIMIT_MEMLOCK"),
            "the knob to turn must be named: {text}"
        );
    }

    /// The negative arm: mapping ENOMEM must not swallow every other errno.
    ///
    /// Without this the mapper could return the memlock message unconditionally
    /// and the test above would still pass, which would turn a bad fd or a
    /// kernel that refuses the opcode into a confident lie about memory limits.
    #[test]
    fn a_registration_failure_that_is_not_enomem_passes_through_unchanged() {
        let original = io::Error::from_raw_os_error(libc::EINVAL);
        let mapped = registration_error(original, FixedSlotRing::required_locked_bytes(), None);
        assert_eq!(mapped.raw_os_error(), Some(libc::EINVAL));
        assert!(
            !mapped.to_string().contains("RLIMIT_MEMLOCK"),
            "an EINVAL must not be dressed up as a memlock shortfall: {mapped}"
        );
    }

    /// The requirement is DERIVED from the pool the SCXML declares, so a round
    /// that resizes the pool moves it here too instead of leaving a stale number
    /// in the lane's provisioning check.
    #[test]
    fn the_locked_byte_requirement_is_the_whole_pool() {
        assert_eq!(
            FixedSlotRing::required_locked_bytes(),
            SLOT_COUNT * SLOT_SIZE
        );
    }
}
