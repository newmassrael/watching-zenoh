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
//! reads through `tokio::io` and nothing selects this path for a production
//! link yet. The atom's status records that residual rather than leaving it to
//! be discovered.
//!
//! ⚠ R2747 — THIS PARAGRAPH USED TO PRESCRIBE THE REPAIR, AND THE
//! PRESCRIPTION WAS WRONG. It said selecting the path "needs the length-prefix
//! sniff to become fixed-buffer aware", which describes a shape the pin does
//! not have: upstream dispatches at task start
//! (`io/zenoh-transport/src/unicast/universal/link.rs` @ `async fn rx_task_uring(`)
//! to a SECOND read body and leaves its framing loop untouched. A loop that
//! sizes its own reads cannot be handed a registered buffer at all, because
//! `READ_FIXED` needs a destination before the prefix that would size it has
//! been read. [`crate::uring::FixedSlotRing::read_framed`] is that second
//! body's read and `crate::link_rx_window` is where the frames inside one
//! completion are found; what is still missing is the TASK that drives the
//! read beside the tokio reactor, and the read still blocks on its completion.
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
use crate::link_rx_window::RxWindow;
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
    /// R2750 — THE TABLE THIS RING REGISTERED, held rather than remembered.
    ///
    /// `IORING_REGISTER_BUFFERS` pins addresses inside the table's storage, so
    /// that storage must outlive the ring. Until this field existed that was a
    /// CONTRACT IN A DOC COMMENT — `register` borrowed the arena for the call
    /// and returned a ring with no lifetime tie, so dropping the table while the
    /// ring lived compiled, and the kernel would then write into freed pages.
    ///
    /// Upstream does not rely on a comment for this either: its own registered
    /// region is reached through an owning handle
    /// (`commons/zenoh-uring/src/linux/reader/buffer_group.rs` @
    /// `arena: Rc<GroupedArenaInner>`, with a `Drop` beside it).
    /// [`LinkRxArena`] is already that shape one refcount up — a `Clone` handle
    /// over an `Arc<NodeTable>` — so holding one here makes the lifetime a fact
    /// of the type instead of a rule a caller has to know.
    ///
    /// It also deletes an invariant nothing checked: every read used to take an
    /// arena as an ARGUMENT, which the caller had to ensure was the same table
    /// the ring registered. Passing a different one produced a `buf_index` from
    /// the wrong table. There is now no second table to pass.
    arena: LinkRxArena,
}

/// One completion the kernel has finished with: the `user_data` its
/// submission carried, and the kernel's own result.
///
/// R2748 — a PAIR and not a length, because a ring serving several links
/// cannot assume the completion it just reaped is the one it is waiting for.
/// `result` is kept RAW (negative is `-errno`) so the routing layer decides
/// what an error means for the link it belongs to; turning it into an
/// `io::Error` here would lose the key it has to be routed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// The `user_data` the submission was pushed under.
    pub key: u64,
    /// The kernel's result: bytes written, `0` for EOF, or `-errno`.
    pub result: i32,
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
        // SAFETY (each attempt): as above. The retry re-submits the SAME
        // iovecs, which still name the same slots — `held` is not released
        // until every attempt is done.
        let result = register_awaiting_reclaim(&ring, &iovecs, Self::required_locked_bytes());
        drop(held);
        result?;

        Ok(Self {
            ring,
            registered,
            // The handle, not a copy: `LinkRxArena` is an `Arc<NodeTable>`, so
            // this is the refcount that keeps the pinned storage alive for as
            // long as the kernel holds its addresses.
            arena: arena.clone(),
        })
    }

    /// R2750 — a destination from THIS RING's own table.
    ///
    /// The only way a caller should reach a slot to read into: taking one from
    /// some other arena is what the `arena` parameters used to permit, and a
    /// frame from a table this ring did not register has no `buf_index` here.
    pub fn take_slot(&mut self) -> LinkRxFrame {
        self.arena.take(SLOT_SIZE)
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

    /// The first `user_data` a caller may spend on something that is NOT a
    /// registered slot.
    ///
    /// R2748 — the `user_data` space is what a reactor demultiplexes
    /// completions by, so the rule that keeps two callers apart has to be
    /// written down once rather than assumed at each. Slot keys are
    /// `0..SLOT_COUNT`, because [`Self::submit_read_fixed`] keys a read by the
    /// `buf_index` it reads into and a slot is held exclusively while its read
    /// is in flight; everything else starts above the table.
    pub const FIRST_FREE_KEY: u64 = SLOT_COUNT as u64;

    /// `user_data` for a cancellation's OWN completion.
    ///
    /// Reserved rather than left to the caller: a cancellation completes like
    /// any other submission and a reactor that mistook it for a read would
    /// look up a key nothing submitted.
    pub const CANCEL_KEY: u64 = u64::MAX - 1;

    /// PUSH one `IORING_OP_READ_FIXED` for `frame`'s slot without waiting for
    /// it. Returns `(bytes asked for, the `user_data` it was pushed under)`;
    /// a `0` first element means nothing was pushed because the frame had no
    /// room.
    ///
    /// R2748 — the SUBMISSION half of [`Self::read_fixed_into`], extracted
    /// because a reactor cannot use the two halves together. The one-shot form
    /// submits and then blocks for its own completion, which is only sound
    /// while ONE read exists; a ring serving several links has to submit here
    /// and reap in [`Self::submit_and_reap`], where a completion is routed by
    /// the key rather than assumed to be the caller's.
    ///
    /// The key is the `buf_index`, which is also the destination slot. That is
    /// not a convenience: it makes "which read completed" and "which slot the
    /// kernel wrote into" one fact, so a reactor cannot pair a completion with
    /// the wrong frame. See [`Self::FIRST_FREE_KEY`] for what that costs a
    /// caller with keys of its own.
    ///
    /// Every refusal [`Self::read_fixed_into`] documented is HERE, because
    /// every one of them is about the submission: a spilled frame is not in
    /// the registration, an address the table does not recognise is a
    /// contradiction, and an index past the registration names someone else's
    /// slot.
    pub fn submit_read_fixed(
        &mut self,
        fd: RawFd,
        frame: &mut LinkRxFrame,
        len: usize,
    ) -> io::Result<(usize, u64)> {
        if !frame.is_pooled() {
            return Err(io::Error::other(
                "a spilled frame is not in the registration; read it the ordinary way",
            ));
        }
        let dst = frame.as_mut().as_mut_ptr();
        // R2750 — the ring's OWN table answers this, not one the caller chose.
        let buf_index = self
            .arena
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
            return Ok((0, buf_index as u64));
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
        Ok((len, buf_index as u64))
    }

    /// PUSH one ORDINARY `IORING_OP_READ` into `buf` under `key`.
    ///
    /// R2748 — the arm a registered read cannot serve. Two callers need it and
    /// neither is a shortcut past the registration: a WAKER fd reads into
    /// eight bytes that are nobody's pool slot, and a link whose table ran dry
    /// holds a SPILLED frame, which is an allocation the kernel was never
    /// handed. `crate::link_rx_arena`'s own dry arm takes the same answer —
    /// "the frame costs an allocation and the steady state keeps its slots" —
    /// and refusing to read at all would turn a transient shortage into a lost
    /// link.
    ///
    /// # Safety
    ///
    /// `buf` must stay allocated, unmoved and untouched by anyone else until
    /// the completion carrying `key` has been reaped. `key` must not collide
    /// with a live slot key (see [`Self::FIRST_FREE_KEY`]) or with
    /// [`Self::CANCEL_KEY`].
    pub unsafe fn submit_read(
        &mut self,
        fd: RawFd,
        buf: *mut u8,
        len: u32,
        key: u64,
    ) -> io::Result<()> {
        let entry = opcode::Read::new(types::Fd(fd), buf, len)
            .offset(u64::MAX) // -1: read at the file's current position
            .build()
            .user_data(key);
        // SAFETY: the caller's contract above is exactly `push`'s, and the
        // queue is not shared so nothing else is mid-push.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "io_uring SQ full"))
        }
    }

    /// PUSH an `IORING_OP_ASYNC_CANCEL` for the submission carrying `target`.
    ///
    /// R2748 — what makes SHUTDOWN sound rather than hopeful. A read in flight
    /// names a buffer the kernel may still write into, so dropping the ring
    /// while one is outstanding drops memory the kernel holds a reference to.
    /// A read on a quiet socket never completes on its own, so waiting it out
    /// is not an option either; cancelling it completes it with `-ECANCELED`,
    /// which is a completion like any other and reaps through the same path.
    ///
    /// `ENOENT` back on the cancellation means the read had already completed,
    /// which is not an error here: the completion is on its way and the caller
    /// is draining until nothing is outstanding.
    pub fn submit_cancel(&mut self, target: u64) -> io::Result<()> {
        let entry = opcode::AsyncCancel::new(target)
            .build()
            .user_data(Self::CANCEL_KEY);
        // SAFETY: a cancellation borrows nothing — its operand is the target's
        // `user_data`, a value — and the queue is not shared.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "io_uring SQ full"))
        }
    }

    /// Submit everything queued, BLOCK until at least one completion, then
    /// drain every completion the kernel has ready into `out`.
    ///
    /// R2748 — this is where the blocking lives now, and moving it here is the
    /// point rather than a side effect. [`Self::read_fixed_into`] blocks in the
    /// CALLER, which is why nothing could drive it from a `tokio` task; a
    /// reactor calls this on a thread of its own and the links it serves get
    /// their completions routed to them.
    ///
    /// Draining ALL ready completions rather than one: `submit_and_wait(1)`
    /// returns when at least one is ready and several links can complete in the
    /// same wakeup. Taking one and parking again would leave the rest sitting
    /// in the completion queue behind a wait that has no reason to return.
    pub fn submit_and_reap(&mut self, out: &mut Vec<Completion>) -> io::Result<()> {
        self.ring.submit_and_wait(1)?;
        let mut cq = self.ring.completion();
        cq.sync();
        for cqe in &mut cq {
            out.push(Completion {
                key: cqe.user_data(),
                result: cqe.result(),
            });
        }
        Ok(())
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
    /// ⚠ R2748 — THIS PARAGRAPH USED TO ARGUE THAT THE BLOCKING WAS FINE
    /// BECAUSE NOTHING COULD DRIVE IT OTHERWISE, and the second half of that
    /// is no longer true. It read: "Blocking on the completion rather than
    /// returning a future: this is the adapter, and how a session's link
    /// drives it alongside the tokio reactor is the residual the module docs
    /// name. A future here would imply an integration that does not exist."
    /// `crate::uring_reactor` is that integration, and it does NOT call this
    /// function: it submits with [`Self::submit_read_fixed`] and reaps with
    /// [`Self::submit_and_reap`] on a thread of its own, which is where a
    /// blocking wait belongs. This form survives as the ONE-READ form — what
    /// this module's own tests drive, and what [`Self::read_framed`] is.
    pub fn read_fixed_into(
        &mut self,
        fd: RawFd,
        frame: &mut LinkRxFrame,
        len: usize,
    ) -> io::Result<usize> {
        let (len, _key) = self.submit_read_fixed(fd, frame, len)?;
        if len == 0 {
            return Ok(0);
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

    /// ONE batch-sized `IORING_OP_READ_FIXED` into one registered slot, FRAMED
    /// IN PLACE. Returns what the kernel wrote; `0` is EOF.
    ///
    /// R2747 — the read of the SECOND body, and it is a second body rather
    /// than a change to the first because that is the shape the pin has.
    /// `crate::poll_framed` cannot be handed a registered buffer without
    /// ceasing to be what it is: it SIZES its reads, asking the stream for
    /// exactly the prefix and then for exactly the payload, and `READ_FIXED`
    /// cannot be asked for a payload whose length has not been read yet.
    /// Upstream does not resolve that ordering — it steps around it,
    /// dispatching at task start
    /// (`io/zenoh-transport/src/unicast/universal/link.rs` @ `async fn rx_task_uring(`)
    /// to a body that reads a BATCH into a registered buffer and finds the
    /// frame boundaries afterwards. [`crate::link_rx_window::RxWindow`] is
    /// where those boundaries are found; this is the read that feeds it.
    ///
    /// A FRESH SLOT PER READ, deliberately. [`LinkRxFrame::truncate`] is
    /// shrink-only — a frame narrowed to a short completion can never be
    /// widened back to the room it started with — so re-reading into the same
    /// frame would ratchet it down to nothing. Taking a slot per read also
    /// puts the release where the window's contract wants it: whatever the
    /// callback was lent has been consumed or copied by the time this returns,
    /// and the slot goes home on the way out.
    ///
    /// A DRY table is refused rather than read into, by
    /// [`Self::read_fixed_into`]'s own spill arm: a spilled frame's bytes are
    /// an allocation the kernel was never handed. The caller's fallback is the
    /// ordinary read path, which is what that refusal names.
    ///
    /// ⚠ STILL BLOCKING on the completion, which is the atom's SECOND residual
    /// and downstream of the first by that atom's own argument. What this adds
    /// is that a fixed-buffer read now produces FRAMES rather than a filled
    /// buffer nobody could cut up; what it does not add is a task driving it
    /// beside the tokio reactor, so nothing yet selects this for a production
    /// link.
    pub fn read_framed<F>(
        &mut self,
        fd: RawFd,
        window: &mut RxWindow,
        width: usize,
        on_frame: &mut F,
    ) -> io::Result<usize>
    where
        F: FnMut(&[u8]),
    {
        let mut frame = self.take_slot();
        let n = self.read_fixed_into(fd, &mut frame, SLOT_SIZE)?;
        if n == 0 {
            return Ok(0);
        }
        window
            .push(frame.as_ref(), width, on_frame)
            .map_err(io::Error::other)?;
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
///
/// ⚠ R2749 — ONE ERRNO, TWO FACTS, AND THIS TOLD THE READER THE WRONG ONE.
/// Until this round every `ENOMEM` ended "raise RLIMIT_MEMLOCK ... to at least
/// {needed} bytes", which is advice only when the limit is BELOW `needed`.
/// Hosted run 35488108252 printed it with `soft=8388608` against
/// `needed=4198400` — telling a reader to raise a limit already at twice the
/// requirement, which is an instruction to do nothing. It stood for two
/// rounds. The remedy is now DERIVED from the comparison the function can
/// already make instead of asserted, so the two facts reach different
/// readers: [`MemlockVerdict::TooSmall`] is a provisioning fact, and
/// [`MemlockVerdict::Contended`] is a transient one.
fn registration_error(err: io::Error, needed: usize, limit: Option<(u64, u64)>) -> io::Error {
    if err.raw_os_error() != Some(libc::ENOMEM) {
        return err;
    }
    let measured = match limit {
        Some((soft, hard)) => format!("RLIMIT_MEMLOCK is soft={soft} hard={hard} bytes"),
        None => String::from("RLIMIT_MEMLOCK could not be read"),
    };
    let remedy = match memlock_verdict(needed, limit) {
        MemlockVerdict::TooSmall => format!(
            "This is a limit, not heap exhaustion: raise RLIMIT_MEMLOCK \
             (ulimit -l, or LimitMEMLOCK= under systemd) to at least {needed} \
             bytes."
        ),
        MemlockVerdict::Contended => String::from(
            "The limit already ADMITS this registration, so raising it is not \
             the remedy: something else holds the locked memory right now. In \
             one process that is usually a ring whose fd has closed but whose \
             pinned pages the kernel has not released yet — io_uring tears a \
             ring down asynchronously, so a registration can outrun its \
             predecessor's reclaim.",
        ),
        MemlockVerdict::Unknown => String::from(
            "The limit could not be read, so whether it admits this \
             registration is unknown; check `ulimit -l` before assuming \
             either.",
        ),
    };
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!(
            "io_uring fixed-buffer registration needs {needed} bytes of LOCKABLE \
             memory ({SLOT_COUNT} pool slots x {SLOT_SIZE} bytes, pinned at \
             registration) and the kernel refused with ENOMEM; {measured}. \
             {remedy}"
        ),
    )
}

/// What an `ENOMEM` from `register_buffers` MEANS, given the limit.
///
/// R2749 — the distinction the single errno hides. `ENOMEM` is the kernel
/// saying "not now"; whether that is permanent or transient is decided by a
/// comparison this code can make and did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemlockVerdict {
    /// The limit is below what one registration needs. Permanent until a
    /// human raises it; retrying is a spin.
    TooSmall,
    /// The limit admits one registration, so the refusal is somebody else's
    /// locked memory and it can go away on its own.
    Contended,
    /// The limit could not be read, so neither can be claimed.
    Unknown,
}

/// Read one `ENOMEM` against the limit. Pure, so the two arms are testable
/// without a syscall and without mutating a process-global limit.
fn memlock_verdict(needed: usize, limit: Option<(u64, u64)>) -> MemlockVerdict {
    match limit {
        None => MemlockVerdict::Unknown,
        Some((soft, _hard)) if (soft as u128) < needed as u128 => MemlockVerdict::TooSmall,
        Some(_) => MemlockVerdict::Contended,
    }
}

/// How long a registration will wait out a predecessor's reclaim, in total.
///
/// Small, because the thing being waited for is a kernel workqueue item and
/// not I/O: the measured gap is one test's duration. Bounded, because a wait
/// with no ceiling turns a permanent shortfall into a hang — and the verdict
/// above already keeps a permanent one from reaching here at all.
const RECLAIM_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// One attempt every this long. Ten attempts inside [`RECLAIM_WAIT`].
const RECLAIM_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// `register_buffers`, waiting out a refusal this code can PROVE is transient.
///
/// R2749 — what hosted run 35488108252 was actually failing on, in both of its
/// red jobs. `io_uring` releases a ring's context — and the pages it pinned —
/// asynchronously after the ring fd closes, so a process that registers, drops
/// and registers again can outrun the kernel's reclaim and be refused for
/// memory that is already on its way back. MEASURED at `soft=hard=8 MiB`
/// against a `needed` of 4198400: ONE registration alone succeeds, and TWO
/// SEQUENTIALLY in one process — the first dropped before the second begins —
/// give `ok` then `ENOMEM`.
///
/// ⚠ THAT REFUTES THE MODEL THE LANE WAS BUILT ON. Layer C1br serializes these
/// tests because "two of them in PARALLEL ask for twice the pool"; serialized
/// is exactly how they were running when this red. `--test-threads=1` cannot
/// serialize a resource the kernel frees on its own schedule.
///
/// This is NOT a blanket retry, which would spin for half a second on every
/// host whose limit is genuinely too small and then report the same failure
/// later. It retries ONLY on [`MemlockVerdict::Contended`] — the limit admits
/// this registration, so the memory is someone else's and can come back. A
/// [`MemlockVerdict::TooSmall`] or [`MemlockVerdict::Unknown`] returns at once,
/// which is what a provisioning fact deserves.
fn register_awaiting_reclaim(
    ring: &IoUring,
    iovecs: &[libc::iovec],
    needed: usize,
) -> io::Result<()> {
    let deadline = std::time::Instant::now() + RECLAIM_WAIT;
    loop {
        // SAFETY: the caller holds every slot these iovecs name for the whole
        // of this call, so each attempt submits the same live, unmoved regions.
        match unsafe { ring.submitter().register_buffers(iovecs) } {
            Ok(()) => return Ok(()),
            Err(e) => {
                let limit = memlock_limit();
                if e.raw_os_error() != Some(libc::ENOMEM)
                    || memlock_verdict(needed, limit) != MemlockVerdict::Contended
                    || std::time::Instant::now() >= deadline
                {
                    return Err(registration_error(e, needed, limit));
                }
                std::thread::sleep(RECLAIM_POLL);
            }
        }
    }
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
///
/// ⚠ R2749 — SERIALIZING THEM IS NOT SUFFICIENT, AND THE PARAGRAPH ABOVE SAYS
/// IT IS. `--test-threads=1` was exactly how these were running when hosted
/// run 35488108252 redded them. MEASURED at `soft=hard=8 MiB` against a
/// `needed` of 4198400: one registration ALONE succeeds; two SEQUENTIALLY in
/// one process — the first dropped before the second begins — give `ok` then
/// `ENOMEM`; the whole lane gives 5 passed / 15 failed. The kernel releases a
/// ring's pinned pages asynchronously after its fd closes, so a test process
/// outruns its own predecessor's reclaim and no thread count can serialize
/// that. [`register_awaiting_reclaim`] is what makes the lane deterministic;
/// the serialization above is kept because it bounds how much can overlap,
/// not because it prevents overlap.
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
    /// R2750 — THE RING ALONE SUFFICES: the caller's arena handle is dropped
    /// before a byte is read, and the registered table is still there.
    ///
    /// The registration pins addresses inside the table's storage, so that
    /// storage has to outlive the ring. This is the claim that it is now the
    /// RING that keeps it alive: nothing but the ring holds a handle past the
    /// `drop` below, the destination comes from `take_slot` (the ring's own
    /// table, the only one it has), and the payload still arrives.
    ///
    /// ⚠ WHAT ITS CONTROL CAN AND CANNOT SAY, recorded rather than implied.
    /// Reverting this fix — dropping the `arena` field and taking the table
    /// back as an argument — does NOT reliably red this test, and that is a
    /// property of the defect, not a weakness in the witness: the old shape
    /// made dropping the table while the ring lived LEGAL, and reading through
    /// it afterwards is undefined behaviour, which an allocator that has not
    /// yet reused the pages performs as if nothing were wrong. The control for
    /// this residual is therefore the COMPILE-TIME one: before, `register`
    /// borrowed the arena for the call and returned a ring with no lifetime
    /// tie, so this test's `drop(arena)` compiled and left the kernel writing
    /// into freed pages; now the same `drop` compiles and is sound, because the
    /// refcount the ring holds is what the pages belong to. Stated here so a
    /// later round grades this against a compile-time claim and does not go
    /// looking for a runtime red that cannot exist.
    #[test]
    fn the_registered_table_outlives_the_callers_handle() {
        let mut arena = LinkRxArena::new();
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        // THE POINT OF THE TEST: the caller is done with the table, and says so.
        drop(arena);

        let payload = b"the ring still owns its registration";
        let mut frame = ring.take_slot();
        assert!(
            frame.is_pooled(),
            "the ring's own table must still serve a slot"
        );

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(payload).expect("write");
        drop(wr);

        let n = ring
            .read_fixed_into(rd.as_raw_fd(), &mut frame, payload.len())
            .expect("READ_FIXED");
        assert_eq!(n, payload.len());
        assert_eq!(
            &frame.as_ref()[..n],
            payload,
            "the kernel wrote into a slot the ring kept alive by itself"
        );
    }

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
            .read_fixed_into(rd.as_raw_fd(), &mut frame, payload.len())
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
            .read_fixed_into(rd.as_raw_fd(), &mut frame, room)
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
            .read_fixed_into(rd.as_raw_fd(), &mut frame, 1)
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
    ///
    /// ⚠ R2749 — THE FIXTURE MOVED ONTO THE OTHER ARM AND HAD TO BE PUT BACK.
    /// It passed `Some((8 MiB, 8 MiB))` against a `needed` of 4198400, which
    /// is a limit at TWICE the requirement — the CONTENDED case, not a
    /// shortfall. It read as a shortfall test only because the message had one
    /// arm then. Now that it has two, a shortfall fixture has to be a limit
    /// genuinely below the need, or this test witnesses the wrong sentence
    /// while keeping the name of the right one.
    #[test]
    fn a_memlock_shortfall_is_reported_as_a_limit_not_as_heap_exhaustion() {
        let mapped = registration_error(
            io::Error::from_raw_os_error(libc::ENOMEM),
            FixedSlotRing::required_locked_bytes(),
            Some((1024 * 1024, 1024 * 1024)),
        );
        let text = mapped.to_string();
        assert!(
            text.contains(&FixedSlotRing::required_locked_bytes().to_string()),
            "the requirement must be named: {text}"
        );
        assert!(
            text.contains("1048576"),
            "the MEASURED limit must be named: {text}"
        );
        assert!(
            text.contains("RLIMIT_MEMLOCK"),
            "the knob to turn must be named: {text}"
        );
        assert!(
            text.contains("raise RLIMIT_MEMLOCK"),
            "a limit below the need must be told to RAISE it: {text}"
        );
    }

    /// R2749 — A LIMIT THAT ALREADY ADMITS THE REGISTRATION MUST NOT BE TOLD
    /// TO RAISE ITSELF.
    ///
    /// This is the sentence hosted run 35488108252 printed with
    /// `soft=8388608` against a `needed` of 4198400: "raise RLIMIT_MEMLOCK ...
    /// to at least 4198400 bytes", which is an instruction to do nothing. One
    /// errno carried two facts and the message asserted the wrong one for two
    /// rounds. The assertion is on the ABSENCE of the raise remedy as well as
    /// the presence of the contention one, because a message that said both
    /// would send a reader to the same wrong place.
    #[test]
    fn a_limit_that_admits_the_registration_is_not_told_to_raise_itself() {
        let mapped = registration_error(
            io::Error::from_raw_os_error(libc::ENOMEM),
            FixedSlotRing::required_locked_bytes(),
            Some((8 * 1024 * 1024, 8 * 1024 * 1024)),
        );
        let text = mapped.to_string();
        assert!(
            !text.contains("raise RLIMIT_MEMLOCK"),
            "the limit is already twice the need; raising it is not the remedy: {text}"
        );
        assert!(
            text.contains("already ADMITS"),
            "the reader must be told the memory is somebody else's: {text}"
        );
    }

    /// The verdict is a COMPARISON, and both sides of it are pinned.
    ///
    /// Read directly rather than through the message, so a rewording cannot
    /// quietly move which arm a given `(needed, limit)` lands on — that is the
    /// defect this pair exists for, one layer down from the prose.
    #[test]
    fn the_verdict_reads_the_limit_against_the_need() {
        let need = FixedSlotRing::required_locked_bytes();
        assert_eq!(
            memlock_verdict(need, Some((need as u64 - 1, need as u64 - 1))),
            MemlockVerdict::TooSmall
        );
        assert_eq!(
            memlock_verdict(need, Some((need as u64, need as u64))),
            MemlockVerdict::Contended,
            "a limit EQUAL to the need admits exactly one registration"
        );
        assert_eq!(memlock_verdict(need, None), MemlockVerdict::Unknown);
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

    /// The extent of every slot in the table, AS THE TABLE HANDS IT OUT.
    ///
    /// R2747 — the oracle a framed payload needs, and it is NOT
    /// [`LinkRxArena::slot_of`]. That one answers "is this address a slot
    /// BASE": the emit's `slot_index_of_ptr` returns `None` unless the offset
    /// from the table's storage divides by the stride, which is right for its
    /// callers — `register` and `read_fixed_into` both hold a frame's first
    /// byte — and wrong for a frame FRAMED OUT of a slot, whose payload starts
    /// past a length prefix. The first draft of the tests below asked `slot_of`
    /// about an interior pointer and read its `None` as "this was copied"; it
    /// means "this is not a base".
    ///
    /// The extents are collected through `take`, the same seam
    /// [`FixedSlotRing::register`] uses to reach slot addresses, rather than
    /// computed here from a base and a stride. A test that did that arithmetic
    /// would agree with a copy that happened to land where the test predicted.
    fn slot_extents(arena: &mut LinkRxArena) -> Vec<std::ops::Range<*const u8>> {
        let held: Vec<LinkRxFrame> = (0..SLOT_COUNT).map(|_| arena.take(SLOT_SIZE)).collect();
        let extents = held.iter().map(|f| f.as_ref().as_ptr_range()).collect();
        drop(held);
        extents
    }

    /// Two frames delivered by ONE completion come out as two, and each one is
    /// read straight out of the registered slot.
    ///
    /// This is the row-3 claim carried through FRAMING rather than stopping at
    /// the buffer. `the_kernel_writes_into_the_frames_own_link_rx_slot` proves
    /// the kernel wrote into the slot; what it cannot say is that anything can
    /// find the frames inside it — a completion is not a frame, and until
    /// [`crate::link_rx_window::RxWindow`] there was nothing here that could
    /// cut one up. The witness is again the ADDRESS: the payload the callback
    /// is handed lies INSIDE one of the extents [`slot_extents`] collected
    /// from the table. A body that copied the completion out before framing it
    /// would deliver the same bytes and fail this.
    ///
    /// TWO frames and not one, because one proves nothing about boundaries: a
    /// reader that handed the whole completion up as a single frame would pass
    /// a one-frame test.
    #[test]
    fn one_completion_carrying_two_frames_is_framed_inside_the_slot() {
        let mut arena = LinkRxArena::new();
        let extents = slot_extents(&mut arena);
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        let mut wire = Vec::new();
        wire.extend_from_slice(&3u16.to_le_bytes());
        wire.extend_from_slice(b"one");
        wire.extend_from_slice(&5u16.to_le_bytes());
        wire.extend_from_slice(b"three");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(&wire).expect("write");
        drop(wr);

        let mut window = RxWindow::new();
        let mut seen: Vec<(Vec<u8>, bool)> = Vec::new();
        let n = ring
            .read_framed(rd.as_raw_fd(), &mut window, 2, &mut |frame: &[u8]| {
                let ptr = frame.as_ptr();
                seen.push((frame.to_vec(), extents.iter().any(|r| r.contains(&ptr))))
            })
            .expect("READ_FIXED + framing");

        assert_eq!(n, wire.len(), "one completion carried the whole wire");
        assert_eq!(
            seen,
            vec![(b"one".to_vec(), true), (b"three".to_vec(), true)],
            "both frames come out, and both are read out of the registered slot"
        );
        assert!(window.between_frames(), "the wire ended on a boundary");
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "the slot goes home when the read returns"
        );
        drop(rd);
    }

    /// A frame SPLIT across two completions comes out once, on the second.
    ///
    /// The case a read-sizing loop never meets and this body always can: the
    /// kernel decides how much it wrote, so a frame can end in the next slot.
    /// The first read must yield nothing and say the stream is mid-frame; the
    /// second must yield the whole frame, assembled — which is also why its
    /// payload is NOT in a slot, and that asymmetry is asserted rather than
    /// left to be inferred from the test above.
    #[test]
    fn a_frame_split_across_two_completions_is_assembled_on_the_second() {
        let mut arena = LinkRxArena::new();
        let extents = slot_extents(&mut arena);
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        let (rd, mut wr) = std::io::pipe().expect("pipe");

        // Prefix plus two of five payload bytes.
        let mut head = Vec::new();
        head.extend_from_slice(&5u16.to_le_bytes());
        head.extend_from_slice(b"ab");
        wr.write_all(&head).expect("write head");

        let mut window = RxWindow::new();
        let mut seen: Vec<(Vec<u8>, bool)> = Vec::new();
        let first = ring
            .read_framed(rd.as_raw_fd(), &mut window, 2, &mut |frame: &[u8]| {
                let ptr = frame.as_ptr();
                seen.push((frame.to_vec(), extents.iter().any(|r| r.contains(&ptr))))
            })
            .expect("READ_FIXED + framing");
        assert_eq!(first, head.len());
        assert!(seen.is_empty(), "half a frame is not a frame");
        assert!(
            !window.between_frames(),
            "the window is mid-frame, which is how a reader tells a truncated \
             stream from a clean end"
        );

        wr.write_all(b"cde").expect("write tail");
        drop(wr);
        let second = ring
            .read_framed(rd.as_raw_fd(), &mut window, 2, &mut |frame: &[u8]| {
                let ptr = frame.as_ptr();
                seen.push((frame.to_vec(), extents.iter().any(|r| r.contains(&ptr))))
            })
            .expect("READ_FIXED + framing");
        assert_eq!(second, 3);
        assert_eq!(
            seen,
            vec![(b"abcde".to_vec(), false)],
            "the frame is assembled from the window's carry, so it is in no \
             slot -- the price of a frame that spans completions"
        );
        assert!(window.between_frames());
        assert_eq!(arena.free_slots(), SLOT_COUNT);
        drop(rd);
    }

    /// EOF reports `0` and is not framed as anything.
    ///
    /// The one completion a framing body must not mistake for data: a
    /// zero-byte read is the peer closing, and `crate::poll_framed` answers it
    /// with `Lost`. This body cannot — it has no `LinkEvent` to return — so it
    /// reports the count and leaves the verdict to the caller, who asks
    /// [`crate::link_rx_window::RxWindow::between_frames`] whether the end was
    /// clean.
    #[test]
    fn an_empty_completion_is_reported_as_eof_and_frames_nothing() {
        let mut arena = LinkRxArena::new();
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        let (rd, wr) = std::io::pipe().expect("pipe");
        drop(wr);

        let mut window = RxWindow::new();
        let n = ring
            .read_framed(rd.as_raw_fd(), &mut window, 2, &mut |_: &[u8]| {
                unreachable!("EOF carries no frame")
            })
            .expect("READ_FIXED at EOF");
        assert_eq!(n, 0, "EOF is a zero-byte completion");
        assert!(
            window.between_frames(),
            "and this one ended cleanly, with nothing carried"
        );
        assert_eq!(arena.free_slots(), SLOT_COUNT);
        drop(rd);
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
