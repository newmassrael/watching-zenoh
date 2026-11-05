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
            Self::Open(_) => "it could not be opened",
            Self::Status(_) => "its status could not be read",
            Self::Read(_) => "it could not be read",
            Self::TooLong => "it is longer than the buffer it is read into",
            Self::Exposed(_) => "it is a secret the group or others may read (chmod 600 it)",
        }
    }
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
}
