// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `freertos-sys` — hand-written FFI for the FreeRTOS-Kernel V11.1.0 core task
//! API used by the watching-zenoh **cooperative single-task profile**
//! (`wz-runtime-freertos`, R311y24+). The vendored kernel C is statically
//! compiled by `build.rs` only on a bare-metal Cortex-M cross target
//! (`vendor/freertos-kernel`, ARM_CM3 port); host builds carry these decls but
//! link nothing.
//!
//! The surface is intentionally minimal: one task hosts the wz cooperative
//! async executor (`run_until_idle` from `wz-runtime-coop`), so the runtime
//! needs only task create / start-scheduler / delay / tick-count / delete plus
//! the heap_4 allocator. Software timers, queues-as-IPC, event groups, and
//! co-routines are disabled in the reference `FreeRTOSConfig.h`.
//!
//! Hand-written (not bindgen) because the FreeRTOS headers are heavily
//! config-macro-dependent; the ABI for these few functions is stable across
//! the ARMv7-M port and a curated surface avoids bindgen's config-coupling.

#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_void};

/// FreeRTOS `BaseType_t` — `long` on the ARMv7-M port (32-bit).
pub type BaseType_t = i32;
/// FreeRTOS `UBaseType_t` — `unsigned long` on the ARMv7-M port (32-bit).
pub type UBaseType_t = u32;
/// FreeRTOS `TickType_t` — 32-bit per `configTICK_TYPE_WIDTH_IN_BITS = 32`.
pub type TickType_t = u32;
/// Opaque `TaskHandle_t` (pointer to the kernel's TCB).
pub type TaskHandle_t = *mut c_void;
/// Task entry point: `void (*)(void *)`.
pub type TaskFunction_t = Option<unsafe extern "C" fn(*mut c_void)>;

/// `xTaskCreate` success.
pub const pdPASS: BaseType_t = 1;
/// `xTaskCreate` failure (e.g. heap exhausted).
pub const pdFAIL: BaseType_t = 0;
pub const pdTRUE: BaseType_t = 1;
pub const pdFALSE: BaseType_t = 0;

extern "C" {
    /// Create a task. `us_stack_depth` is in WORDS (matches
    /// `configSTACK_DEPTH_TYPE = uint16_t`), not bytes. Returns [`pdPASS`] or
    /// [`pdFAIL`].
    pub fn xTaskCreate(
        px_task_code: TaskFunction_t,
        pc_name: *const c_char,
        us_stack_depth: u16,
        pv_parameters: *mut c_void,
        ux_priority: UBaseType_t,
        px_created_task: *mut TaskHandle_t,
    ) -> BaseType_t;

    /// Start the scheduler. Does not return on success (the idle task + the
    /// created tasks run); only returns if there was insufficient heap for the
    /// idle/timer tasks.
    pub fn vTaskStartScheduler();

    /// Block the calling task for `xticks_to_delay` ticks.
    pub fn vTaskDelay(xticks_to_delay: TickType_t);

    /// Delete a task (`NULL` = the calling task).
    pub fn vTaskDelete(x_task_to_delete: TaskHandle_t);

    /// Ticks since `vTaskStartScheduler` — the cooperative profile's
    /// `ClockSource` (monotonic, `configTICK_RATE_HZ`-resolution).
    pub fn xTaskGetTickCount() -> TickType_t;

    /// heap_4 allocator (the `#[global_allocator]` for the FreeRTOS profile
    /// bridges to these).
    pub fn pvPortMalloc(x_wanted_size: usize) -> *mut c_void;
    /// Free a block from [`pvPortMalloc`].
    pub fn vPortFree(pv: *mut c_void);

    /// ARMv7-M port exception handlers — the deploy crate's cortex-m-rt vector
    /// table routes `SVCall` / `PendSV` / `SysTick` to these (indirect routing;
    /// `configCHECK_HANDLER_INSTALLATION = 0`).
    pub fn vPortSVCHandler();
    pub fn xPortPendSVHandler();
    pub fn xPortSysTickHandler();
}
