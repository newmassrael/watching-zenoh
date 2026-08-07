// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y589 — `runtime-tokio-uring`: ARCHITECTURE §9.5 row 3.
//!
//! The §9.5 table's claim is that ONE pool lifecycle FSM serves every platform
//! and only the EDGE ACTIONS differ. Row 1 arms a DMA controller; row 2 waits on
//! `epoll` and copies; row 3 hands the kernel a registered `iovec` and submits
//! `IORING_OP_READ_FIXED`. Until this module the table had one incarnation, so
//! the claim was an assertion about code that did not exist.
//!
//! [`crate::zero_copy`] built row 2's pool consumer. This is row 3's, over the
//! SAME pool: the buffers registered with the kernel here are literally
//! `reassembly_pool_ap`'s slots, which is why `runtime-tokio-uring` implies
//! `runtime-zero-copy` rather than sitting beside it.
//!
//! ## What "zero-copy" means on this path, precisely
//!
//! Row 2 reads into a link buffer and the chain then stages a copy of it. Here
//! the kernel writes into the pool slot the chain already holds, and completion
//! only advances a length ([`PooledStaging::commit_external`]). There is no
//! intermediate buffer, which is the RFC's own definition of the RX happy path
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

use std::io;
use std::os::fd::RawFd;

use io_uring::{opcode, types, IoUring};

use crate::reassembly_pool_ap::{SLOT_COUNT, SLOT_SIZE};
use crate::zero_copy::{PooledChain, PooledStaging};

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
    /// Build a ring and register every slot of `staging`'s pool as a fixed
    /// buffer, in slot-index order — so a pool slot index IS its `buf_index`
    /// and the two never need a mapping table to drift out of.
    ///
    /// # Safety contract, upheld by the signature
    ///
    /// Registered buffers must stay at their addresses until the ring is
    /// dropped. `PooledStaging` holds its pool in a `Box`, so the storage does
    /// not move when the arena does; taking `&mut PooledStaging` for the call
    /// and returning an owned ring does NOT by itself pin the arena, so the
    /// caller must keep it alive — which [`Self::read_fixed`] cannot check and
    /// the tests below therefore state explicitly by scoping both together.
    pub fn register<const SLOTS: usize, const CAP: usize>(
        staging: &mut PooledStaging<SLOTS, CAP>,
        entries: u32,
    ) -> io::Result<Self> {
        let ring = IoUring::new(entries)?;

        // The slot addresses, read through the GENERATED API rather than by
        // reaching into the pool's private storage: acquire each slot, take its
        // pointer, and hand it straight back. The borrow from `write` ends at
        // the end of its statement, which is what lets N pointers be collected
        // without N live mutable borrows.
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(SLOT_COUNT);
        let mut held = Vec::with_capacity(SLOT_COUNT);
        while let Some(mut chain) = staging.acquire_raw() {
            iovecs.push(libc::iovec {
                iov_base: staging.slot_ptr(&mut chain) as *mut libc::c_void,
                iov_len: SLOT_SIZE,
            });
            held.push(chain);
        }
        let registered = iovecs.len();
        // Register BEFORE returning the slots: the pointers are valid either
        // way (the storage belongs to the pool, not to the handle), but holding
        // them across the call is what makes "every slot, in index order" true
        // rather than a race with another acquirer.
        //
        // SAFETY: each iovec points at one `[u8; SLOT_SIZE]` inside the pool's
        // boxed storage, which outlives this call and — per the type-level
        // contract above — the ring.
        let result = unsafe { ring.submitter().register_buffers(&iovecs) };
        for chain in held {
            staging.release_raw(chain);
        }
        result?;

        Ok(Self { ring, registered })
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

    /// `IORING_OP_READ_FIXED` from `fd` APPENDED into `chain`'s pool slot, at
    /// most `len` bytes and never past `CAP`. Returns what the kernel wrote and
    /// advances the chain by it.
    ///
    /// The signature takes the arena and the chain rather than a bare index,
    /// and that is a correctness fix rather than ergonomics. The first version
    /// took `(fd, buf_index, len)` and passed a null `addr`, on the reading that
    /// `buf_index` alone tells the kernel where to write. It does not:
    /// `READ_FIXED`'s `addr` is the ACTUAL destination and must lie inside the
    /// registered region that `buf_index` names — a null one is `EFAULT`, which
    /// is what the test reported. Deriving the address from the chain makes the
    /// only expressible target the right one, and makes the append offset
    /// (`staged_len`) part of the same derivation instead of a second thing to
    /// keep in step.
    ///
    /// Blocking on the completion rather than returning a future: this is the
    /// adapter, and how a session's link drives it alongside the tokio reactor
    /// is the residual the module docs name. A future here would imply an
    /// integration that does not exist.
    pub fn read_fixed_into<const SLOTS: usize, const CAP: usize>(
        &mut self,
        fd: RawFd,
        staging: &mut PooledStaging<SLOTS, CAP>,
        chain: &mut PooledChain,
        len: usize,
    ) -> io::Result<usize> {
        let buf_index = chain.slot_idx();
        assert!(
            buf_index < self.registered,
            "buf_index {buf_index} is not a registered pool slot ({} registered)",
            self.registered
        );
        let offset = chain.staged_len();
        // Never let the kernel write past what the chain may hold: `CAP` is the
        // Router's bound and `SLOT_SIZE` the registration's, and the smaller one
        // wins. Without this the completion could report more than
        // `commit_external` will accept, and the bytes would already be written.
        let room = CAP.min(SLOT_SIZE).saturating_sub(offset);
        let len = len.min(room);
        if len == 0 {
            return Ok(0);
        }
        let dst = unsafe { staging.slot_ptr(chain).add(offset) };

        let entry = opcode::ReadFixed::new(types::Fd(fd), dst, len as u32, buf_index as u16)
            .offset(u64::MAX) // -1: read at the file's current position
            .build()
            .user_data(buf_index as u64);

        // SAFETY: `dst` is `offset` bytes into the registered region named by
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
        staging
            .commit_external(chain, n)
            .map_err(|_| io::Error::other("the kernel wrote more than the chain may hold"))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wz_session_core::chain_staging::ChainStaging;

    /// The AP arena's own dims: the registration covers the whole pool either
    /// way, so using anything else here would only hide that.
    type Arena = PooledStaging<SLOT_COUNT, SLOT_SIZE>;

    /// Every pool slot is registered, in index order.
    ///
    /// The count is the assertion that separates "the registration ran" from
    /// "the registration ran and registered nothing" — a ring with zero buffers
    /// accepts `register_buffers` and then fails every read with `EFAULT`, which
    /// reads like a bad fd rather than like an empty registration.
    #[test]
    fn registration_covers_every_pool_slot() {
        let mut arena: Arena = ChainStaging::new();
        let ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");
        assert_eq!(ring.registered(), SLOT_COUNT);
        assert_eq!(
            arena.pool().free_count(),
            SLOT_COUNT,
            "registration must hand every slot back"
        );
    }

    /// THE ROW-3 CLAIM: the kernel writes into the pool slot itself.
    ///
    /// Not "a read succeeded" — that would pass with an ordinary `READ` into a
    /// scratch buffer. The bytes are read back through the CHAIN's own view
    /// (`ChainStaging::bytes`), which is a borrow of the generated pool's
    /// storage, so the only way this passes is if `IORING_OP_READ_FIXED` landed
    /// in the registered region that IS that slot. Nothing in this test copies.
    #[test]
    fn the_kernel_writes_into_the_chains_own_pool_slot() {
        let mut arena: Arena = ChainStaging::new();
        let mut ring = FixedSlotRing::register(&mut arena, 8).expect("io_uring registration");

        let mut chain = ChainStaging::<SLOT_COUNT, SLOT_SIZE>::acquire(&mut arena)
            .expect("a fresh pool has slots");
        let idx = chain.slot_idx();

        let payload = b"read-fixed straight into the pool slot";
        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(payload).expect("write");
        drop(wr);

        use std::os::fd::AsRawFd;
        let n = ring
            .read_fixed_into(rd.as_raw_fd(), &mut arena, &mut chain, payload.len())
            .expect("READ_FIXED");
        assert_eq!(n, payload.len());
        assert_eq!(chain.staged_len(), payload.len());
        assert_eq!(chain.slot_idx(), idx, "the chain kept its slot");

        assert_eq!(
            ChainStaging::<SLOT_COUNT, SLOT_SIZE>::bytes(&arena, &chain),
            payload,
            "the bytes must be readable through the POOL SLOT, not a copy"
        );

        // The slot is still the chain's, and the lifecycle FSM says so.
        assert_eq!(
            arena.pool().free_count(),
            SLOT_COUNT - 1,
            "the chain still holds its slot after the kernel wrote to it"
        );
        drop(rd);
        ChainStaging::<SLOT_COUNT, SLOT_SIZE>::release(&mut arena, chain);
        assert_eq!(arena.pool().free_count(), SLOT_COUNT);
    }

    /// `commit_external` is bounded by the same rule `append` is, so a kernel
    /// that returned more than asked cannot silently widen a chain past `CAP`.
    #[test]
    fn commit_external_refuses_past_the_cap() {
        let mut arena: PooledStaging<4, 64> = ChainStaging::new();
        let mut chain = ChainStaging::<4, 64>::acquire(&mut arena).expect("slots");
        assert!(arena.commit_external(&mut chain, 64).is_ok());
        assert!(
            arena.commit_external(&mut chain, 1).is_err(),
            "one byte past CAP must be refused"
        );
        ChainStaging::<4, 64>::release(&mut arena, chain);
    }
}
