// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `bytes` module in the shared-memory arm (the first slice of the top crate):
//! upstream's crate (`up_zenoh`) and wz's (`wz_zenoh`) given the same payloads, results equal as
//! text.
//!
//! * a payload that is not in shared memory has no buffer of it, and neither has an empty one;
//! * a payload built from a buffer of a provider has its buffer back, with the same bytes, in one
//!   slice, and the mutable access is refused for it;
//! * a payload built from a mutable buffer, and one that holds the buffer among other slices (which
//!   has none).
//!
//! The crates share the machine's segments, so the tests of this binary take one lock.

#![cfg(target_os = "linux")]

use std::sync::{Mutex, MutexGuard};

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

macro_rules! shm_cases {
    ($name:ident, $z:ident, $core:ident) => {
        mod $name {
            use $core::Wait;
            use $z::{
                bytes::ZBytes,
                shm::{AllocAlignment, MemoryLayout, ShmProviderBuilder, ZShm, ZShmMut},
            };

            pub fn scenario() -> Vec<String> {
                let mut out = vec![];
                let mut plain = ZBytes::from("not in shm");
                out.push(format!(
                    "plain as_shm {} as_shm_mut {}",
                    plain.as_shm().is_some(),
                    plain.as_shm_mut().is_some()
                ));
                out.push(format!("empty as_shm {}", ZBytes::new().as_shm().is_some()));
                let layout = MemoryLayout::new(8192, AllocAlignment::ALIGN_8_BYTES).unwrap();
                let provider = ShmProviderBuilder::default_backend(layout).wait().unwrap();
                let mut buf = provider.alloc(100usize).wait().unwrap();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = i as u8;
                }
                let immutable: ZShm = buf.into();
                let mut z = ZBytes::from(immutable);
                out.push(format!(
                    "shm: len {} as_shm {} bytes {:02x?} slices {}",
                    z.len(),
                    z.as_shm().is_some(),
                    z.to_bytes().iter().take(8).collect::<Vec<_>>(),
                    z.slices().count()
                ));
                out.push(format!("shm as_shm_mut {}", z.as_shm_mut().is_some()));
                let cloned = z.clone();
                out.push(format!(
                    "clone: as_shm {} equal {}",
                    cloned.as_shm().is_some(),
                    cloned == z
                ));
                let buf2: ZShmMut = provider.alloc(50usize).wait().unwrap();
                let z2 = ZBytes::from(buf2);
                out.push(format!("shm mut: len {} as_shm {}", z2.len(), z2.as_shm().is_some()));
                let mut w = ZBytes::writer();
                w.append(z.clone());
                w.append(ZBytes::from("tail"));
                let two = w.finish();
                out.push(format!(
                    "two slices: len {} as_shm {} slices {}",
                    two.len(),
                    two.as_shm().is_some(),
                    two.slices().count()
                ));
                out
            }
        }
    };
}

shm_cases!(up, up_zenoh, up_core);
shm_cases!(wz, wz_zenoh, wz_core);

#[test]
fn a_payload_and_its_buffer_in_shared_memory() {
    let _g = serial();
    let (u, w) = (up::scenario(), wz::scenario());
    assert!(u.iter().any(|l| l.contains("as_shm true")), "no buffer was found in a payload: {u:#?}");
    assert!(u.iter().any(|l| l.contains("as_shm false")), "no payload without a buffer: {u:#?}");
    assert_eq!(u, w);
}

#[test]
fn the_comparison_sees_a_scenario_that_differs() {
    let _g = serial();
    let u = up::scenario();
    let mut w = wz::scenario();
    w[2] = format!("{} changed", w[2]);
    assert_ne!(u, w);
}
