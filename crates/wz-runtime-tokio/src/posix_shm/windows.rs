// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows segment: a pagefile-backed NAMED file mapping, the way upstream's
//! `shm::windows::SegmentImpl` makes one (`commons/zenoh-shm/src/shm/windows.rs` @
//! `CreateFileMapping(`). The platform-neutral half (the id source and its
//! injectivity rationale) lives in the parent module.
//!
//! What differs from the Unix segment, all of it upstream's own shape:
//!
//! * the NAME is the same string, `"{id}.zenoh"`, but it names a kernel object in
//!   the session's local namespace instead of a file under `/dev/shm`. A zenoh
//!   peer on the same machine opens exactly this string, which is what makes the
//!   segment interop;
//! * there is no file, no mode and no advisory lock. The kernel keeps the object
//!   alive for as long as any process holds a handle to it, and drops the name
//!   with the last handle, so a crashed creator leaves nothing to sweep:
//!   upstream's orphan cleanup is a no-op here (`commons/zenoh-shm/src/posix_shm/cleanup.rs`
//!   @ `#[cfg(not(target_os = "linux"))]`), and so is this one;
//! * a mapping can never go stale. A holder keeps its handle, the name stays bound
//!   to the object that handle names, and no other object can take it, so
//!   `is_current` is true for as long as the value exists. The Unix twin has to ask
//!   because there an owner can unlink the name from under a reader.
//! * the size a PEER reads back is the pages the kernel committed (upstream reads
//!   it with `VirtualQuery` for the same reason), which is the creator's size
//!   rounded up to a page. The creator's own value is the size it asked for.

use std::io;
use std::ptr::null;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualQuery,
    FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS,
    PAGE_READWRITE, SEC_COMMIT,
};

use super::SEGMENT_DEDICATE_TRIES;

/// The object name upstream's `CreateFileMapping` is given, as the NUL-terminated
/// UTF-16 string the wide API takes. This name IS interop: a foreign peer opens
/// exactly this string.
fn segment_name(id: u64) -> Vec<u16> {
    format!("{id}.zenoh")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// One mapped view of a named mapping, and the handle that keeps the mapping alive.
/// The three segment types are this plus what each of them says about it.
struct View {
    handle: HANDLE,
    ptr: *mut u8,
    len: usize,
}

// SAFETY: `handle` and `ptr` name a kernel object and a view of it, neither of which is
// tied to the thread that made it; the pointer is only ever handed out as a raw pointer
// whose uses are the caller's.
unsafe impl Send for View {}
// SAFETY: as for `Send`; sharing the value shares the address of a mapping that is itself
// shared memory, and nothing reached through `&self` writes it.
unsafe impl Sync for View {}

impl View {
    /// Map the whole of `handle` with `access`, taking ownership of the handle: it is
    /// closed here when the mapping fails, and on drop otherwise. `size` is the
    /// length to report, or `None` to ask the kernel what it committed.
    fn map(handle: HANDLE, access: u32, size: Option<usize>) -> io::Result<Self> {
        // SAFETY: `handle` is a live file-mapping handle this function owns; offset 0 and
        // length 0 map the whole object, and the call has no other effect on process state.
        let view = unsafe { MapViewOfFile(handle, access, 0, 0, 0) };
        let ptr = view.Value.cast::<u8>();
        if ptr.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: `handle` is owned here and not used again.
            unsafe { CloseHandle(handle) };
            return Err(err);
        }
        let len = match size {
            Some(len) => len,
            None => match committed_len(ptr) {
                Ok(len) => len,
                Err(err) => {
                    // SAFETY: `ptr` is the view just mapped and `handle` the mapping that
                    // made it; neither is used again.
                    unsafe {
                        UnmapViewOfFile(view);
                        CloseHandle(handle);
                    }
                    return Err(err);
                }
            },
        };
        Ok(Self { handle, ptr, len })
    }

    /// Open the existing mapping named by `id` and map it with `access`.
    fn open(id: u64, access: u32) -> io::Result<Self> {
        let name = segment_name(id);
        // SAFETY: `name` is NUL-terminated and outlives the call; the call has no other
        // effect on process state.
        let handle = unsafe { OpenFileMappingW(access, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Self::map(handle, access, None)
    }
}

/// The size the kernel committed for the view at `ptr`: upstream's `VirtualQuery` read.
fn committed_len(ptr: *const u8) -> io::Result<usize> {
    // SAFETY: an all-zero `MEMORY_BASIC_INFORMATION` is a valid value of a plain C struct.
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `ptr` is inside a live view, and `info` is a writable buffer of the size
    // passed.
    let written = unsafe {
        VirtualQuery(
            ptr.cast(),
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info.RegionSize)
    }
}

impl Drop for View {
    fn drop(&mut self) {
        // Best-effort, as the Unix unlink is: a failure leaks a view until the process
        // exits, which is not worth a panic inside a drop.
        // SAFETY: `ptr` is the view `MapViewOfFile` returned and `handle` the mapping it
        // was made from; nothing uses either after this.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.ptr.cast(),
            });
            CloseHandle(self.handle);
        }
    }
}

/// Orphan cleanup. A no-op, as upstream's is off Linux: the kernel drops a mapping's
/// name with its last handle, so a crashed creator leaves no segment behind.
pub fn cleanup_orphaned_segments() {}

/// A segment THIS process created: mapped read-write, and gone with its last handle.
pub struct OwnedSegment {
    view: View,
    id: u64,
}

impl OwnedSegment {
    /// Create a segment of `len` bytes under the first free id `next_id`
    /// yields, trying at most [`SEGMENT_DEDICATE_TRIES`] of them. The new
    /// segment is zero-filled (a fresh pagefile-backed object).
    pub fn create(len: usize, mut next_id: impl FnMut() -> u64) -> io::Result<Self> {
        let mut last_err = None;
        let size = len as u64;
        for _ in 0..SEGMENT_DEDICATE_TRIES {
            let id = next_id();
            let name = segment_name(id);
            // SAFETY: `name` is NUL-terminated and outlives the call; INVALID_HANDLE_VALUE
            // is how a pagefile-backed object is asked for, and a null security descriptor
            // is the default one.
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    null(),
                    PAGE_READWRITE | SEC_COMMIT,
                    (size >> 32) as u32,
                    size as u32,
                    name.as_ptr(),
                )
            };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // CreateFileMappingW answers an existing name with a handle to THAT object and
            // sets this code; it is read at once, before any other call can replace it.
            // SAFETY: reads the calling thread's last-error value.
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                // SAFETY: `handle` is owned here and not used again.
                unsafe { CloseHandle(handle) };
                last_err = Some(io::Error::from_raw_os_error(ERROR_ALREADY_EXISTS as i32));
                continue;
            }
            let view = View::map(handle, FILE_MAP_READ | FILE_MAP_WRITE, Some(len))?;
            return Ok(Self { view, id });
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::other(format!(
                "could not dedicate a shm segment after {SEGMENT_DEDICATE_TRIES} tries"
            ))
        }))
    }

    /// The id this segment is named by — the value a peer is told.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The segment's bytes.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the view is `len` bytes, valid for as long as `self` lives.
        unsafe { std::slice::from_raw_parts(self.view.ptr, self.view.len) }
    }

    /// The segment's bytes, writable.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `bytes`, and `&mut self` is the one writer this value hands out.
        unsafe { std::slice::from_raw_parts_mut(self.view.ptr, self.view.len) }
    }

    /// The segment's first byte, as a pointer that may be written through. Valid for
    /// [`Self::len`] bytes for as long as `self` lives. This is how a chunk of a pool is
    /// reached: by an address into the mapping, not by a reference to all of it.
    pub fn base(&self) -> *mut u8 {
        self.view.ptr
    }

    /// The segment's size in bytes.
    pub fn len(&self) -> usize {
        self.view.len
    }

    /// Whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.view.len == 0
    }

    /// Nothing to flush: the object has no file behind it.
    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// A segment ANOTHER process created, opened by id and mapped read-only.
pub struct PeerSegment {
    view: View,
}

impl PeerSegment {
    /// Open the segment named by `id`. An error — never a panic — when it does
    /// not exist or cannot be mapped: to a caller that is "this peer
    /// holds no such segment", which is an ordinary outcome of shared memory.
    pub fn open(id: u64) -> io::Result<Self> {
        Ok(Self {
            view: View::open(id, FILE_MAP_READ)?,
        })
    }

    /// The segment's bytes.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the view is `len` bytes, valid for as long as `self` lives. The peer may
        // write it concurrently, which is the shared-memory contract; every reader of this
        // view reads fields whose torn value fails a comparison rather than being unsound.
        unsafe { std::slice::from_raw_parts(self.view.ptr, self.view.len) }
    }

    /// Whether the name this segment was opened by still names the same object. Always
    /// true here: this value holds a handle to the object, and a name cannot be bound
    /// to another object while a handle to the first is open.
    pub fn is_current(&self) -> bool {
        true
    }
}

/// A segment ANOTHER process created, opened by id and mapped READ-WRITE, for a
/// reader that has to write what it reads (the `refcount` it gives back).
///
/// What is exposed is a POINTER with write provenance, not a `&[u8]`: the
/// contents are atomics, and a shared reference to bytes is a promise that
/// nothing writes them.
pub struct PeerSegmentRw {
    view: View,
}

impl PeerSegmentRw {
    /// Open the segment named by `id`. An error, never a panic, when it does not
    /// exist or cannot be mapped, as for [`PeerSegment::open`].
    pub fn open(id: u64) -> io::Result<Self> {
        Ok(Self {
            view: View::open(id, FILE_MAP_READ | FILE_MAP_WRITE)?,
        })
    }

    /// Whether the name this segment was opened by still names the same object.
    /// Always true, for the reason [`PeerSegment::is_current`] gives.
    pub fn is_current(&self) -> bool {
        true
    }

    /// The segment's size in bytes.
    pub fn len(&self) -> usize {
        self.view.len
    }

    /// Whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.view.len == 0
    }

    /// The segment's first byte, as a pointer that may be written through. Valid
    /// for [`Self::len`] bytes for as long as `self` lives.
    pub fn base(&self) -> *mut u8 {
        self.view.ptr
    }
}

#[cfg(test)]
mod tests {
    use super::super::next_candidate_id;
    use super::*;

    /// A segment created here is opened by id as a peer, sees the creator's writes in
    /// both mappings, and is gone once every handle is closed. The peer's length is
    /// the committed pages, so it is at least what was asked for.
    #[test]
    fn a_peer_sees_what_the_owner_wrote_and_the_name_dies_with_the_last_handle() {
        let mut owner =
            OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        assert_eq!(owner.len(), 64);
        owner.bytes_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);

        let id = owner.id();
        let reader = PeerSegment::open(id).expect("open read-only");
        let writer = PeerSegmentRw::open(id).expect("open writable");
        assert!(reader.bytes().len() >= 64);
        assert_eq!(&reader.bytes()[..4], &[1, 2, 3, 4]);
        assert!(reader.is_current() && writer.is_current());

        // SAFETY: `writer` maps at least 64 bytes and no other thread touches them.
        unsafe { writer.base().add(4).write(9) };
        assert_eq!(
            owner.bytes()[4],
            9,
            "a write through a peer reaches the owner"
        );

        drop(owner);
        assert!(
            PeerSegment::open(id).is_ok(),
            "the peers' handles keep the object, and so its name, alive"
        );
        drop(reader);
        drop(writer);
        assert!(
            PeerSegment::open(id).is_err(),
            "the last handle closed, so the name is gone"
        );
    }

    /// A name already bound is refused rather than shared: `create` moves on to the next
    /// id, so two creators never get one object.
    #[test]
    fn create_skips_an_id_whose_name_is_taken() {
        let first = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let taken = first.id();
        let mut offered = vec![taken, taken];
        offered.push(u64::from(next_candidate_id()));
        let mut ids = offered.into_iter();
        let second = OwnedSegment::create(64, || ids.next().expect("an id")).expect("create");
        assert_ne!(second.id(), taken, "the taken name was passed over");
    }
}
