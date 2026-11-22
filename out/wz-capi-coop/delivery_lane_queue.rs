// SCE-GENERATED — DO NOT EDIT
// source-hash: b9060efffeb926b8f725394ced574956af5f16b11c339805541743fe3417d56e
// source: delivery_lane_queue.scxml
// SCE-MAP: delivery_lane_queue.scxml:30 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="queue")
// Runtime: sce_forge_runtime::queue
// Do not edit — regenerate from the source SCXML file.
//
// SCE Protocol-Synthesis RFC §synth-5-P queue — a first-in first-out queue
// that hands elements from one execution context to another. The document
// states the contract (element type, one producer(s), one
// consumer(s), `wait-free`) and names no algorithm; the algorithm
// below is what the selection table gives that contract, and the memory
// ordering is part of it, not a choice.
//
// Selected: Lamport ring. Push is wait-free, pop is wait-free.
//
// Operations (from `sce_forge_runtime::queue`):
//   try_push(&producer, element) -> Result<(), PushError<T>>
//   try_pop(&consumer)           -> Option<T>
//   capacity()                   -> usize
// A full queue rejects the push and hands the element back.


use sce_forge_runtime::queue::spsc::Spsc;
use super::delivery_lane_handle::DeliveryLaneHandle;

/// The most elements the queue holds (`<sce:bounded>`).
pub const CAPACITY: usize = 64;

/// What the document requires of push and pop (`<sce:progress>`).
pub const DECLARED_PROGRESS: &str = "wait-free";
/// What the selected algorithm gives push.
pub const PUSH_PROGRESS: &str = "wait-free";
/// What the selected algorithm gives pop.
pub const POP_PROGRESS: &str = "wait-free";
/// The algorithm the selection table gave this contract.
pub const ALGORITHM: &str = "Lamport ring";

/// The queue. It owns its storage and allocates nothing, so it may be a
/// `static`; elements still in it when it is dropped are dropped with it.
pub type DeliveryLaneQueue = Spsc<DeliveryLaneHandle, CAPACITY>;

/// The bytes of storage the queue occupies, for a target that budgets them.
pub const STORAGE_BYTES: usize = core::mem::size_of::<DeliveryLaneQueue>();