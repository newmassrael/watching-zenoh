// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A file read whole into a buffer the caller owns: what a program with no allocator reads a
//! document it is given at run time with (a node's identity, provisioned to the device apart from
//! the program).
//!
//! A secret ([`read_secret`]) is read only when no one but its owner may read it, the rule `ssh`
//! holds a private key to: a key the group or the world can read is a key that is no longer the
//! device's alone, and a program that used it anyway would present an identity it cannot vouch
//! for.

use core::ffi::CStr;

// The sentences are the identity contract's, shared with the C library's identity door.
use wz_session_core::identity_provision::file_words;

/// Why a file was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRefused {
    /// The file could not be opened (`errno`).
    Open(i32),
    /// Its status could not be read (`errno`).
    Status(i32),
    /// A read failed (`errno`).
    Read(i32),
    /// It is longer than the buffer, which keeps one byte for the terminating NUL.
    TooLong,
    /// A secret the group or others may read: its mode, as `stat` gives it.
    Exposed(u32),
}

impl FileRefused {
    /// The console line's reason.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Open(_) => file_words::NOT_OPENED,
            Self::Status(_) => file_words::NO_STATUS,
            Self::Read(_) => file_words::NOT_READ,
            Self::TooLong => file_words::TOO_LONG,
            Self::Exposed(_) => file_words::EXPOSED,
        }
    }
}

/// Why a file was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRefused {
    /// A file (or anything else) is at the path already, and is left as it is.
    Exists,
    /// The file could not be made (`errno`).
    Open(i32),
    /// A write failed (`errno`); what was made is removed.
    Write(i32),
    /// What was written could not be made durable (`errno`); what was made is removed.
    Sync(i32),
}

impl CreateRefused {
    /// The console line's reason.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Exists => file_words::EXISTS,
            Self::Open(_) => file_words::NOT_MADE,
            Self::Write(_) => file_words::NOT_WRITTEN,
            Self::Sync(_) => file_words::NOT_DURABLE,
        }
    }
}

/// Whether anything is at `path` (a dangling link counts: it is not followed).
pub fn exists(path: &CStr) -> bool {
    // SAFETY: an all-zero `stat` is a valid value for the kernel to overwrite.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: `path` is NUL-terminated and `status` is live and writable.
    unsafe { libc::lstat(path.as_ptr(), &mut status) == 0 }
}

/// Make the file at `path` with `bytes` in it, and nothing if anything is there already: the file
/// is opened with `O_CREAT | O_EXCL`, so two makers race to one winner and a file that is there is
/// never replaced. A secret is made readable by its owner alone (0600) from the moment it exists,
/// the mode [`read_secret`] takes; any other file 0644, less what the process's umask removes. The
/// bytes are on the device's storage when this returns. On a failure after the file was made, it is
/// removed again, so a file is there whole or not at all.
pub fn create_new(path: &CStr, bytes: &[u8], secret: bool) -> Result<(), CreateRefused> {
    let mode: libc::c_uint = if secret { 0o600 } else { 0o644 };
    // SAFETY: `path` is NUL-terminated; the descriptor is this call's own, closed below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(match errno() {
            libc::EEXIST => CreateRefused::Exists,
            e => CreateRefused::Open(e),
        });
    }
    let result = write_open(fd, bytes);
    // SAFETY: `fd` is open and this call's own, closed exactly once.
    unsafe { libc::close(fd) };
    if result.is_err() {
        // The file this call made, which holds less than it was given.
        remove(path);
    }
    result
}

/// Remove the file at `path`, if it is there: what a caller made with [`create_new`] and must
/// take back.
pub fn remove(path: &CStr) {
    // SAFETY: `path` is NUL-terminated.
    unsafe { libc::unlink(path.as_ptr()) };
}

/// Write `bytes` to the open file `fd` and make them durable.
fn write_open(fd: i32, mut bytes: &[u8]) -> Result<(), CreateRefused> {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is live for its length; `fd` is open.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        match n {
            n if n > 0 => bytes = &bytes[n as usize..],
            _ if errno() == libc::EINTR => {}
            _ => return Err(CreateRefused::Write(errno())),
        }
    }
    // SAFETY: `fd` is open.
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(CreateRefused::Sync(errno()));
    }
    Ok(())
}

/// Read the file at `path` into `buf`, followed by a NUL, and hand back the text as a C string.
pub fn read_into<'b>(path: &CStr, buf: &'b mut [u8]) -> Result<&'b CStr, FileRefused> {
    read(path, buf, false)
}

/// [`read_into`] for a secret: refused, unread, when the group or others may read it.
pub fn read_secret<'b>(path: &CStr, buf: &'b mut [u8]) -> Result<&'b CStr, FileRefused> {
    read(path, buf, true)
}

use crate::net::errno;

fn read<'b>(path: &CStr, buf: &'b mut [u8], secret: bool) -> Result<&'b CStr, FileRefused> {
    // SAFETY: `path` is NUL-terminated; the descriptor is this call's own, closed below.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(FileRefused::Open(errno()));
    }
    let result = read_open(fd, buf, secret);
    // SAFETY: `fd` is open and this call's own, closed exactly once.
    unsafe { libc::close(fd) };
    let len = result?;
    buf[len] = 0;
    CStr::from_bytes_with_nul(&buf[..=len]).map_err(|_| FileRefused::Read(0))
}

/// Read the open file `fd` into `buf`, keeping one byte for the NUL: its length.
fn read_open(fd: i32, buf: &mut [u8], secret: bool) -> Result<usize, FileRefused> {
    if secret {
        // SAFETY: an all-zero `stat` is a valid value for the kernel to overwrite.
        let mut status: libc::stat = unsafe { core::mem::zeroed() };
        // SAFETY: `fd` is open and `status` is live and writable.
        if unsafe { libc::fstat(fd, &mut status) } != 0 {
            return Err(FileRefused::Status(errno()));
        }
        // `mode_t` is 32 bits on Linux and Neutrino and 16 on 32-bit bionic.
        #[allow(clippy::useless_conversion)]
        let mode = u32::from(status.st_mode);
        if mode & 0o077 != 0 {
            return Err(FileRefused::Exposed(mode));
        }
    }
    let room = buf.len().checked_sub(1).ok_or(FileRefused::TooLong)?;
    let mut len = 0;
    loop {
        if len == room {
            // The buffer is full: the file is longer exactly when one more byte is there.
            let mut probe = [0u8; 1];
            // SAFETY: `probe` is live and writable for one byte; `fd` is open.
            let more = unsafe { libc::read(fd, probe.as_mut_ptr().cast(), 1) };
            return match more {
                0 => Ok(len),
                n if n > 0 => Err(FileRefused::TooLong),
                _ => Err(FileRefused::Read(errno())),
            };
        }
        // SAFETY: `buf[len..room]` is live and writable; `fd` is open.
        let got = unsafe { libc::read(fd, buf[len..room].as_mut_ptr().cast(), room - len) };
        match got {
            0 => return Ok(len),
            n if n > 0 => len += n as usize,
            _ if errno() == libc::EINTR => {}
            _ => return Err(FileRefused::Read(errno())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::format;
    use std::os::unix::fs::PermissionsExt;

    fn written(name: &str, body: &[u8], mode: u32) -> (std::path::PathBuf, CString) {
        let path = std::env::temp_dir().join(format!("wz-file-{}-{name}", std::process::id()));
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let c = CString::new(path.to_str().unwrap()).unwrap();
        (path, c)
    }

    #[test]
    fn a_file_is_read_whole_and_terminated() {
        let (path, c) = written("whole", b"hello", 0o644);
        let mut buf = [0xffu8; 16];
        assert_eq!(read_into(&c, &mut buf).unwrap().to_bytes(), b"hello");
        // Exactly as long as the room left beside the NUL is read whole too.
        let mut tight = [0u8; 6];
        assert_eq!(read_into(&c, &mut tight).unwrap().to_bytes(), b"hello");
        let mut short = [0u8; 5];
        assert_eq!(read_into(&c, &mut short), Err(FileRefused::TooLong));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_secret_others_may_read_is_refused_unread_and_one_only_its_owner_may_read_is_read() {
        let (path, c) = written("secret", b"key", 0o640);
        let mut buf = [0u8; 16];
        assert!(matches!(
            read_secret(&c, &mut buf),
            Err(FileRefused::Exposed(_))
        ));
        assert_eq!(buf, [0u8; 16], "nothing of an exposed secret is read");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret(&c, &mut buf).unwrap().to_bytes(), b"key");
        std::fs::remove_file(path).unwrap();
        assert!(matches!(
            read_secret(&c, &mut buf),
            Err(FileRefused::Open(_))
        ));
    }

    /// A new secret is made its owner's alone and read back as one; a file that is there already
    /// is never replaced, and is left with what it held.
    #[test]
    fn a_new_file_is_made_whole_and_one_that_is_there_is_never_replaced() {
        let path = std::env::temp_dir().join(format!("wz-file-{}-made", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c = CString::new(path.to_str().unwrap()).unwrap();
        assert!(!exists(&c));
        create_new(&c, b"first", true).expect("made");
        assert!(exists(&c));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a secret is its owner's alone from the start");
        let mut buf = [0u8; 16];
        assert_eq!(read_secret(&c, &mut buf).unwrap().to_bytes(), b"first");
        assert_eq!(
            create_new(&c, b"second", true),
            Err(CreateRefused::Exists),
            "a file that is there is not made again"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"first",
            "and keeps what it held"
        );
        std::fs::remove_file(path).unwrap();
    }
}
