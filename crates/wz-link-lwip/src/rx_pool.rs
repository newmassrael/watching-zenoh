// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y599 — the MCU receive seam: slots the reader borrows and returns,
//! over the SCE-generated buffer-pool lifecycle FSM.
//!
//! ## Why this exists
//!
//! Until this module the four `out/wz-link-lwip/*_pool_mcu.rs` emits were
//! consumed for their CONSTANTS only — [`rx_sockets`](crate::rx_sockets)
//! turned `SLOT_COUNT` / `SLOT_SIZE` into `LwipUdpSocket<N, Q>` const
//! generics and the seven-state slot lifecycle had zero callers. The pool was
//! a dimension oracle, not a pool. [`RxSlots`] is the seam that makes it one.
//!
//! ## The seam's shape, and what it deliberately hides
//!
//! A reader asks for the bytes of a received datagram and says when it is
//! done. It does NOT learn how the bytes got into the slot. That is the whole
//! point: on the host / QEMU profile the CPU copies them out of an lwIP
//! `pbuf`, and on a descriptor-ring MAC the peripheral writes them directly.
//! Both end at the same place — a slot holding `len` bytes, borrowed then
//! returned — so both can sit behind this trait without the session tier
//! branching on which one it got.
//!
//! ## What this trait is NOT, stated so it is not stretched later
//!
//! It is the pool-facing half: reserve, fill, read, release. It does not
//! model the ARMING half (`link_arm_rx` -> `dma_start_rx` -> `rx_complete`),
//! because arming needs something this API does not give: the ADDRESS of a
//! slot that is armed but not yet filled, to hand to a MAC's buffer-request
//! callback.
//!
//! R311y606 — that used to read "cannot be built", measured against the emit
//! at vendor/sce `ef4c2fe4d5`, where `Slot<DmaArmedRx>` carried only `idx()`
//! and the pool's `storage` was private. It was sent upstream and answered:
//! `62794d8c4b` publishes the address and the reverse map, and the arm half
//! now lives in [`rx_ring`](crate::rx_ring). A CPU-fill adapter still needs
//! none of it, which is why the two halves are still two traits.
//!
//! Nor does it model a CIRCULAR-DMA source (zenoh-pico's serial port,
//! `vendor/zenoh-pico/src/system/threadx/stm32/network.c:4`), where the
//! peripheral writes a ring continuously and software reads behind it. That
//! shape has no reserve/release pair at all and must not be forced through
//! this one.
//!
//! ## The accounting gate
//!
//! [`RxSlots::free_count`] is the reason this seam is worth having beyond
//! tidiness: a reader that drops a slot instead of releasing it shows up as a
//! freelist that never returns to `SLOT_COUNT`. That is exactly the failure
//! SCE shipped and fixed at `4f31430001` — a pool whose arm edge had no
//! return path died on first use, and no consumer could see it because no
//! consumer counted. The tests below count.

use alloc::boxed::Box;

use core::ffi::c_void;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr::NonNull;

use heapless::spsc::Queue;
use lwip_sys::{
    err_enum_t_ERR_OK, ip_addr_t, pbuf, pbuf_alloc, pbuf_copy_partial, pbuf_free,
    pbuf_layer_PBUF_TRANSPORT, pbuf_take, pbuf_type_PBUF_RAM, u16_t, udp_bind, udp_new, udp_pcb,
    udp_recv, udp_remove, udp_sendto,
};

use crate::{LinkError, LwipLink};

/// A pool of fixed-size receive slots with a borrow-then-return discipline.
///
/// Implemented over each SCE-generated `sce:kind="buffer-pool"` emit by
/// [`impl_rx_slots`]. The associated [`Slot`](RxSlots::Slot) is the emit's own
/// phantom-typed handle, so the lifecycle rules the generator encodes —
/// `pool_return` on a slot the peripheral owns is a type error, not a runtime
/// check — survive being seen through this trait.
pub trait RxSlots {
    /// Slots in the pool. From the buffer-pool SSOT, not chosen here.
    const SLOT_COUNT: usize;
    /// Bytes per slot. From the same SSOT.
    const SLOT_SIZE: usize;

    /// A reserved slot. Opaque: the reader holds it and gives it back.
    type Slot;

    /// A pool with every slot on the freelist.
    fn new() -> Self;

    /// Take a slot off the freelist, or `None` when every slot is out.
    ///
    /// `None` is back-pressure, not an error: the caller drops the datagram
    /// and counts it, which is what a bounded receive path must do.
    fn reserve(&mut self) -> Option<Self::Slot>;

    /// Writable bytes of a reserved slot — where a CPU filler copies to, and
    /// the full [`SLOT_SIZE`](RxSlots::SLOT_SIZE) width regardless of how much
    /// the filler will use.
    fn buf<'a>(&'a mut self, slot: &'a mut Self::Slot) -> &'a mut [u8];

    /// Readable bytes of a slot, full width. The caller pairs this with the
    /// length it recorded at fill time; the pool does not track lengths,
    /// because a length belongs to a datagram and a slot outlives none.
    fn bytes<'a>(&'a self, slot: &'a Self::Slot) -> &'a [u8];

    /// Return a slot to the freelist. Consumes the handle, so a reader cannot
    /// keep reading bytes it has released.
    fn release(&mut self, slot: Self::Slot);

    /// Slots currently on the freelist. The accounting gate — see the module
    /// docs.
    fn free_count(&self) -> usize;

    /// Pool index of a held slot, for tracing and for the tests that assert on
    /// the emit's own `slot_state` rather than on this trait's bookkeeping.
    fn slot_idx(slot: &Self::Slot) -> usize;
}

/// Implement [`RxSlots`] over one SCE-generated buffer-pool emit.
///
/// Every emit has the same shape (`pool_acquire_for_encode` / `write` /
/// `read` / `pool_return` / `free_count`), so the impl is mechanical — but it
/// is written out per pool rather than made generic because the emitted
/// `Slot<CpuMut>` types are DISTINCT per pool by construction: a slot from the
/// scout pool must not be returnable to the session pool, and keeping the
/// types apart is what makes that a compile error.
macro_rules! impl_rx_slots {
    ($pool_mod:ident, $pool_ty:ident) => {
        impl RxSlots for crate::$pool_mod::$pool_ty {
            const SLOT_COUNT: usize = crate::$pool_mod::SLOT_COUNT;
            const SLOT_SIZE: usize = crate::$pool_mod::SLOT_SIZE;

            type Slot = crate::$pool_mod::Slot<crate::$pool_mod::CpuMut>;

            fn new() -> Self {
                <crate::$pool_mod::$pool_ty>::new()
            }

            fn reserve(&mut self) -> Option<Self::Slot> {
                self.pool_acquire_for_encode()
            }

            fn buf<'a>(&'a mut self, slot: &'a mut Self::Slot) -> &'a mut [u8] {
                &mut slot.write(self)[..]
            }

            fn bytes<'a>(&'a self, slot: &'a Self::Slot) -> &'a [u8] {
                &slot.read(self)[..]
            }

            fn release(&mut self, slot: Self::Slot) {
                slot.pool_return(self);
            }

            fn free_count(&self) -> usize {
                <crate::$pool_mod::$pool_ty>::free_count(self)
            }

            fn slot_idx(slot: &Self::Slot) -> usize {
                slot.idx()
            }
        }
    };
}

impl_rx_slots!(scout_rx_pool_mcu, ScoutRxPoolMcu);
impl_rx_slots!(session_rx_pool_mcu_multicast, SessionRxPoolMcuMulticast);

// The unicast session pool is ONE module under two names: the default emit or
// the slim one, never both (`lib.rs:116,136`). The impl carries the same gate
// as the module it names — a helper whose cfg is narrower than the item it
// calls is the G7 shape, and here it is the emit that is gated, so the impl
// must be too.
#[cfg(not(feature = "buffer-pool-session-rx-slim"))]
impl_rx_slots!(session_rx_pool_mcu, SessionRxPoolMcu);
#[cfg(feature = "buffer-pool-session-rx-slim")]
impl_rx_slots!(session_rx_pool_mcu_minimal, SessionRxPoolMcuMinimal);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// The CPU-fill adapter: an lwIP UDP socket whose received bytes land in
// pool slots instead of an inline `heapless::Vec` per queue entry.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// One received datagram: the slot holding it, how much of the slot is
/// live, and who sent it.
///
/// Not public — a caller never holds this, because holding it would mean
/// holding a slot, and the borrow-then-return discipline exists precisely so
/// that cannot happen by accident. [`PooledUdpRx::recv_with`] lends the bytes
/// and takes the slot back before it returns.
struct Received<S> {
    slot: S,
    len: usize,
    src_addr: u32,
    src_port: u16,
}

struct PooledInner<P: RxSlots, const Q: usize> {
    pcb: NonNull<udp_pcb>,
    pool: P,
    queue: Queue<Received<P::Slot>, Q>,
    rx_drops: u32,
    _pin: PhantomPinned,
}

// Same rationale as `Inner`: referenced only under lwIP's NO_SYS=1
// cooperative model, and the raw pcb pointer is what rules out the automatic
// impl.
unsafe impl<P: RxSlots, const Q: usize> Send for PooledInner<P, Q> {}

/// A UDP receive socket that stages into an [`RxSlots`] pool.
///
/// The CPU-fill adapter named in this module's docs: the recv callback copies
/// the lwIP `pbuf` into a reserved slot, and [`recv_with`](Self::recv_with)
/// lends those bytes to a closure and returns the slot. A descriptor-ring
/// adapter would fill the slot by peripheral instead and expose the same
/// `recv_with`, which is the point of putting the closure at this boundary.
///
/// `Q` is the queue depth and must not exceed the pool's `SLOT_COUNT` — a
/// deeper queue than there are slots could never fill, and asserting it at
/// construction turns that into a startup failure rather than a permanent
/// under-run. Note `heapless::spsc::Queue<T, Q>` holds `Q - 1`, so the
/// pool always has at least one slot spare for the in-flight fill.
pub struct PooledUdpRx<P: RxSlots, const Q: usize> {
    inner: Pin<Box<PooledInner<P, Q>>>,
}

unsafe extern "C" fn pooled_recv_thunk<P: RxSlots, const Q: usize>(
    arg: *mut c_void,
    _pcb: *mut udp_pcb,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    port: u16_t,
) {
    // SAFETY: `arg` is the `*mut PooledInner<P, Q>` handed to udp_recv at
    // bind; the Pin<Box<..>> keeps it at a stable address and NO_SYS=1 means
    // no concurrent borrow. Each (P, Q) gets its own monomorphisation.
    let inner = unsafe { &mut *(arg as *mut PooledInner<P, Q>) };

    if p.is_null() {
        return;
    }

    // Read the source before the pbuf is freed: lwIP may point `addr` into
    // the chain itself.
    let src_addr = if addr.is_null() {
        0
    } else {
        // SAFETY: non-null and valid while `p` is live; copied by value.
        unsafe { (*addr).addr }
    };
    // SAFETY: the callback owns `p` per the lwIP contract.
    let len = unsafe { (*p).tot_len as usize };

    // Reserve BEFORE copying. A pool with nothing free is back-pressure, and
    // the datagram is dropped with a count rather than partially staged.
    let Some(mut slot) = inner.pool.reserve() else {
        inner.rx_drops = inner.rx_drops.saturating_add(1);
        // SAFETY: caller-owned pbuf, freed exactly once on this path.
        unsafe { pbuf_free(p) };
        return;
    };

    let copy_len = core::cmp::min(len, P::SLOT_SIZE);
    {
        let buf = inner.pool.buf(&mut slot);
        // SAFETY: `buf` is SLOT_SIZE bytes and `copy_len <= SLOT_SIZE`;
        // pbuf_copy_partial writes exactly `copy_len`.
        unsafe {
            pbuf_copy_partial(p, buf.as_mut_ptr() as *mut c_void, copy_len as u16, 0);
        }
    }
    // SAFETY: caller-owned pbuf, freed exactly once.
    unsafe {
        pbuf_free(p);
    }

    let received = Received {
        slot,
        len: copy_len,
        src_addr,
        src_port: port,
    };
    if let Err(rejected) = inner.queue.enqueue(received) {
        // THE LEAK THAT WOULD OTHERWISE HIDE: a full queue must give the slot
        // back, or a burst permanently shrinks the freelist and the socket
        // goes quiet with no error anywhere. `free_count` is what makes this
        // visible, and `a_full_queue_returns_the_slot_it_could_not_hold`
        // is what proves it.
        inner.pool.release(rejected.slot);
        inner.rx_drops = inner.rx_drops.saturating_add(1);
    }
}

impl<P: RxSlots, const Q: usize> PooledUdpRx<P, Q> {
    /// Bind a fresh UDP pcb to `IP_ADDR_ANY:port` with a pool-backed receive
    /// path.
    ///
    /// # Panics
    ///
    /// If `Q > P::SLOT_COUNT` — a queue deeper than the pool can fill is a
    /// configuration error, and failing at bind is better than a socket that
    /// silently never reaches its declared depth.
    ///
    /// # Errors
    ///
    /// - [`LinkError::PcbExhausted`] if `udp_new` returns NULL.
    /// - [`LinkError::BindFailed`] if `udp_bind` rejects the port.
    pub fn bind(_link: &LwipLink, port: u16) -> Result<Self, LinkError> {
        assert!(
            Q <= P::SLOT_COUNT,
            "rx queue depth exceeds the pool's slot count"
        );
        let mut inner: Pin<Box<PooledInner<P, Q>>> = Box::pin(PooledInner {
            pcb: NonNull::dangling(),
            pool: P::new(),
            queue: Queue::new(),
            rx_drops: 0,
            _pin: PhantomPinned,
        });

        // SAFETY: no-arg allocator out of MEMP_NUM_UDP_PCB.
        let pcb_raw = unsafe { udp_new() };
        let Some(pcb) = NonNull::new(pcb_raw) else {
            return Err(LinkError::PcbExhausted);
        };

        let any: ip_addr_t = ip_addr_t { addr: 0 };
        // SAFETY: pcb valid, &any spans the call.
        let bind_err = unsafe { udp_bind(pcb.as_ptr(), &any, port) };
        if bind_err as core::ffi::c_int != err_enum_t_ERR_OK {
            // SAFETY: freshly allocated pcb; remove releases it.
            unsafe { udp_remove(pcb.as_ptr()) };
            return Err(LinkError::BindFailed(bind_err));
        }

        // SAFETY: pinned; only the pcb field is mutated, and the raw address
        // taken here stays valid for the socket's lifetime.
        let inner_mut = unsafe { Pin::get_unchecked_mut(inner.as_mut()) };
        inner_mut.pcb = pcb;
        let arg = inner_mut as *mut PooledInner<P, Q> as *mut c_void;
        // SAFETY: pcb + callback + arg all valid; the monomorphised thunk
        // matches the `PooledInner<P, Q>` cast inside it.
        unsafe { udp_recv(pcb.as_ptr(), Some(pooled_recv_thunk::<P, Q>), arg) };

        Ok(Self { inner })
    }

    /// Lend the next datagram's bytes to `f`, then return its slot.
    ///
    /// `None` when nothing has arrived since the last call. The closure — and
    /// not a returned value — is the seam: the bytes live in a pool slot, so
    /// handing them out by value would mean a copy and handing them out by
    /// reference would mean the caller holding a slot. This way the slot is
    /// back on the freelist before the call returns, on every path.
    pub fn recv_with<R>(&mut self, f: impl FnOnce(&[u8], u32, u16) -> R) -> Option<R> {
        // SAFETY: Pin<Box<..>> is address-stable; the borrow is scoped here.
        let inner = unsafe { Pin::get_unchecked_mut(self.inner.as_mut()) };
        let received = inner.queue.dequeue()?;
        let out = {
            let bytes = &inner.pool.bytes(&received.slot)[..received.len];
            f(bytes, received.src_addr, received.src_port)
        };
        inner.pool.release(received.slot);
        Some(out)
    }

    /// Send to `dst_addr:dst_port`; `dst_addr` is lwIP-native network byte
    /// order. Payload longer than the pool's slot width is truncated, mirroring
    /// the receive side's cap so a socket cannot send what it could not receive.
    pub fn send_to(
        &mut self,
        dst_addr: u32,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), LinkError> {
        let len = payload.len().min(P::SLOT_SIZE) as u16;
        // SAFETY: returns an owned pbuf chain or null.
        let p = unsafe { pbuf_alloc(pbuf_layer_PBUF_TRANSPORT, len, pbuf_type_PBUF_RAM) };
        if p.is_null() {
            return Err(LinkError::PbufAlloc);
        }
        // SAFETY: p has capacity `len`; payload ptr valid for `len`.
        let take_err = unsafe { pbuf_take(p, payload.as_ptr() as *const c_void, len) };
        if take_err as core::ffi::c_int != err_enum_t_ERR_OK {
            // SAFETY: free the pbuf we allocated.
            unsafe { pbuf_free(p) };
            return Err(LinkError::SendFailed(take_err));
        }
        let dst: ip_addr_t = ip_addr_t { addr: dst_addr };
        // SAFETY: pcb valid (Inner owns it), p valid, &dst spans the call.
        let send_err = unsafe { udp_sendto(self.inner.pcb.as_ptr(), p, &dst, dst_port) };
        if send_err as core::ffi::c_int != err_enum_t_ERR_OK {
            // SAFETY: the stack did not take ownership on the error path.
            unsafe { pbuf_free(p) };
            return Err(LinkError::SendFailed(send_err));
        }
        Ok(())
    }

    /// Slots currently on the freelist — the accounting gate, exposed so a
    /// deploy can watch it rather than only the tests.
    pub fn free_slots(&self) -> usize {
        self.inner.pool.free_count()
    }

    /// Datagrams dropped because the pool was drained or the queue was full.
    /// Both are back-pressure and both count here; they are distinguishable by
    /// reading [`free_slots`](Self::free_slots) alongside.
    pub fn rx_drop_count(&self) -> u32 {
        self.inner.rx_drops
    }
}

impl<P: RxSlots, const Q: usize> Drop for PooledUdpRx<P, Q> {
    fn drop(&mut self) {
        // Clear the callback before removing the pcb, so a datagram arriving
        // mid-drop cannot dispatch into a freed Inner. Same order as
        // `LwipUdpSocket`.
        // SAFETY: pcb valid; None + null is lwIP's documented teardown.
        unsafe {
            udp_recv(self.inner.pcb.as_ptr(), None, core::ptr::null_mut());
            udp_remove(self.inner.pcb.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ACTIVE unicast session pool under either feature arm, so the slim
    // lane runs these tests too rather than compiling them out. A `#[cfg]` on
    // the tests themselves would leave the slim build asserting nothing about
    // the seam while still reporting green.
    #[cfg(not(feature = "buffer-pool-session-rx-slim"))]
    use crate::session_rx_pool_mcu::{SessionRxPoolMcu as ActiveSessionPool, SlotState};
    #[cfg(feature = "buffer-pool-session-rx-slim")]
    use crate::session_rx_pool_mcu_minimal::{
        SessionRxPoolMcuMinimal as ActiveSessionPool, SlotState,
    };

    /// The dims reaching the trait are the SSOT's. Asserted against
    /// [`crate::rx_sockets`]' constants rather than against literals, because
    /// those two are the pool's only consumers and the whole hazard is them
    /// disagreeing: `rx_sockets` sizes the socket, this seam sizes the slots,
    /// and a pool whose two readers picked different numbers would truncate
    /// silently.
    #[test]
    fn the_trait_carries_the_same_dims_the_socket_tier_reads() {
        std::assert_eq!(
            <ActiveSessionPool as RxSlots>::SLOT_COUNT,
            crate::rx_sockets::SESSION_RX_SLOTS
        );
        std::assert_eq!(
            <ActiveSessionPool as RxSlots>::SLOT_SIZE,
            crate::rx_sockets::SESSION_RX_SLOT_SIZE
        );
    }

    /// A full reserve -> fill -> read -> release cycle, driving the EMIT's
    /// lifecycle rather than this trait's bookkeeping: the slot's state is
    /// read back out of the generated `slot_state`, so a trait that "worked"
    /// while leaving the FSM untouched would fail here.
    #[test]
    fn one_cycle_moves_the_emitted_state_and_returns_the_slot() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT
        );

        let mut slot = pool.reserve().expect("a fresh pool has a free slot");
        let idx = <ActiveSessionPool as RxSlots>::slot_idx(&slot);
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::CpuMut));
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT - 1
        );

        let payload: &[u8] = b"r311y599 cpu-filled slot";
        pool.buf(&mut slot)[..payload.len()].copy_from_slice(payload);
        std::assert_eq!(&pool.bytes(&slot)[..payload.len()], payload);

        pool.release(slot);
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::Free));
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT
        );
    }

    /// THE ACCOUNTING GATE. Cycle every slot in the pool several times over
    /// and require the freelist back at `SLOT_COUNT` each round.
    ///
    /// This is the shape of the defect SCE shipped and fixed at `4f31430001`:
    /// a pool whose slots left the freelist and had no path back died after
    /// `SLOT_COUNT` uses, silently, because nothing counted. Asserting only
    /// that `reserve` returned `Some` would pass on that pool for exactly one
    /// round and then wedge, so the loop runs three.
    #[test]
    fn the_freelist_returns_to_full_after_every_round() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;

        for round in 0..3 {
            let mut held = std::vec::Vec::new();
            for i in 0..count {
                let slot = pool
                    .reserve()
                    .unwrap_or_else(|| std::panic!("round {round}: slot {i} of {count} refused"));
                held.push(slot);
            }
            std::assert_eq!(
                pool.free_count(),
                0,
                "round {round}: pool should be drained"
            );
            std::assert!(
                pool.reserve().is_none(),
                "round {round}: a drained pool must refuse, not overcommit"
            );

            for slot in held {
                pool.release(slot);
            }
            std::assert_eq!(
                pool.free_count(),
                count,
                "round {round}: every slot must be back on the freelist"
            );
        }
    }

    /// Slots are distinct: filling one does not disturb another. Guards the
    /// index arithmetic the emit does on its `storage` array — an off-by-one
    /// there would alias two readers onto one buffer, which no state assertion
    /// would catch.
    #[test]
    fn two_slots_do_not_alias() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        let mut a = pool.reserve().expect("slot a");
        let mut b = pool.reserve().expect("slot b");
        std::assert_ne!(
            <ActiveSessionPool as RxSlots>::slot_idx(&a),
            <ActiveSessionPool as RxSlots>::slot_idx(&b)
        );

        pool.buf(&mut a)[..4].copy_from_slice(b"AAAA");
        pool.buf(&mut b)[..4].copy_from_slice(b"BBBB");

        std::assert_eq!(&pool.bytes(&a)[..4], b"AAAA");
        std::assert_eq!(&pool.bytes(&b)[..4], b"BBBB");

        pool.release(a);
        pool.release(b);
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT
        );
    }

    /// The CPU-fill adapter end to end: loop a datagram back to itself and
    /// take it through `recv_with`. Proves the recv callback staged into a
    /// POOL slot (not an inline buffer) and that the closure saw the bytes.
    #[test]
    fn pooled_socket_loopback_round_trip() {
        let (_serial, link) = crate::lwip_test_link();
        let port: u16 = 7451;
        let mut sock: PooledUdpRx<ActiveSessionPool, 4> =
            PooledUdpRx::bind(&link, port).expect("bind pooled rx");
        let full = <ActiveSessionPool as RxSlots>::SLOT_COUNT;
        std::assert_eq!(sock.free_slots(), full);

        let payload: &[u8] = b"r311y599 pooled recv_with";
        sock.send_to(crate::ipv4_addr_loopback(), port, payload)
            .expect("send_to 127.0.0.1");
        link.poll_loopback();
        link.check_timeouts();

        // While the datagram sits in the queue its slot is OUT of the pool —
        // asserted so a "slot" that was never actually reserved would fail
        // here rather than pass the round trip by copying.
        std::assert_eq!(sock.free_slots(), full - 1);

        let seen = sock
            .recv_with(|bytes, _addr, src_port| (bytes.to_vec(), src_port))
            .expect("one datagram");
        std::assert_eq!(&seen.0[..], payload);
        std::assert_eq!(seen.1, port);

        // ...and back on the freelist the moment recv_with returned.
        std::assert_eq!(sock.free_slots(), full);
        std::assert_eq!(sock.rx_drop_count(), 0);
        std::assert!(sock.recv_with(|_, _, _| ()).is_none());
    }

    /// THE LEAK GUARD. Overflow the receive queue and require every slot back
    /// on the freelist afterwards.
    ///
    /// `heapless::spsc::Queue<T, Q>` holds `Q - 1`, so binding with `Q = 2`
    /// and sending four datagrams overflows it. The enqueue-failure path must
    /// hand its slot back; if it drops the slot instead, the socket loses one
    /// slot per overflowed datagram and eventually goes permanently silent
    /// with no error anywhere. That failure is invisible to a drop COUNTER —
    /// the count rises either way — which is why this asserts `free_slots`.
    #[test]
    fn a_full_queue_returns_the_slot_it_could_not_hold() {
        let (_serial, link) = crate::lwip_test_link();
        let port: u16 = 7452;
        let mut sock: PooledUdpRx<ActiveSessionPool, 2> =
            PooledUdpRx::bind(&link, port).expect("bind pooled rx");
        let full = <ActiveSessionPool as RxSlots>::SLOT_COUNT;

        for i in 0..4u8 {
            sock.send_to(crate::ipv4_addr_loopback(), port, &[i; 8])
                .expect("send_to 127.0.0.1");
            link.poll_loopback();
            link.check_timeouts();
        }

        // Q = 2 holds one; the other three were refused by the queue.
        std::assert_eq!(
            sock.rx_drop_count(),
            3,
            "three datagrams should have overflowed"
        );
        // The one still queued holds a slot; the three refused must NOT.
        std::assert_eq!(
            sock.free_slots(),
            full - 1,
            "an overflowed datagram must give its slot back"
        );

        // Draining returns the last one too.
        std::assert!(sock.recv_with(|_, _, _| ()).is_some());
        std::assert_eq!(sock.free_slots(), full);
    }

    /// Each pool is a SEPARATE implementor with its own dims, so the scout
    /// pool's 8 / 256 cannot be mistaken for the session pool's 16 / 1536.
    /// The types being distinct is what stops a scout slot being released
    /// into the session pool; this only pins that the dims travel with them.
    #[test]
    fn each_pool_brings_its_own_dims() {
        use crate::scout_rx_pool_mcu::ScoutRxPoolMcu;
        use crate::session_rx_pool_mcu_multicast::SessionRxPoolMcuMulticast;

        std::assert_eq!(<ScoutRxPoolMcu as RxSlots>::SLOT_COUNT, 8);
        std::assert_eq!(<ScoutRxPoolMcu as RxSlots>::SLOT_SIZE, 256);
        std::assert_eq!(<SessionRxPoolMcuMulticast as RxSlots>::SLOT_COUNT, 32);
        std::assert_eq!(<SessionRxPoolMcuMulticast as RxSlots>::SLOT_SIZE, 1536);

        let mut scout = <ScoutRxPoolMcu as RxSlots>::new();
        let s = scout.reserve().expect("scout slot");
        std::assert_eq!(scout.free_count(), 7);
        scout.release(s);
        std::assert_eq!(scout.free_count(), 8);
    }
}
