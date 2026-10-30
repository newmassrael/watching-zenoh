//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.2, file
// src/posix_shm/cleanup.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

pub(crate) use platform::cleanup_orphaned_segments;

// One module, whose items exist on the platform that has them: the original declares two modules
// of one name, each behind its own `cfg`, which no build rejects and a lint of this tree does.
mod platform {
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn cleanup_orphaned_segments() {}

    #[cfg(target_os = "linux")]
    pub(crate) use linux::cleanup_orphaned_segments;

    #[cfg(target_os = "linux")]
    mod linux {
        use std::fs;

        use zenoh_result::ZResult;

        use crate::shm;

        pub(crate) fn cleanup_orphaned_segments() {
            if let Err(_e) = cleanup_orphaned_segments_inner() {
                // NOTE (debt-910): we cannot use our logger inside of atexit() callstack!
                //tracing::error!("Error performing orphaned SHM segments cleanup: {e}")
            }
        }

        fn cleanup_orphaned_segments_inner() -> ZResult<()> {
            #[cfg(shm_external_lockfile)]
            let shm_files = fs::read_dir(std::env::temp_dir())?;
            #[cfg(not(shm_external_lockfile))]
            let shm_files = fs::read_dir("/dev/shm")?;

            for segment_file in shm_files.filter_map(Result::ok).filter(|f| {
                if let Some(ext) = f.path().extension() {
                    return ext == "zenoh";
                }
                false
            }) {
                if let Some(Some(id_str)) = segment_file
                    .path()
                    .file_stem()
                    .map(|os_str| os_str.to_str())
                {
                    if let Ok(id) = id_str.parse::<u64>() {
                        shm::Segment::ensure_not_persistent(id);
                    }
                }
            }

            Ok(())
        }
    }
}
