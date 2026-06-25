/*
 * SPDX-License-Identifier: MIT
 *
 * mcu-freertos-demo FreeRTOSConfig.h — the DEPLOY config (supplied to
 * freertos-sys via WZ_FREERTOS_CONFIG). Based on
 * crates/freertos-sys/port/cross-test/FreeRTOSConfig.h (mps2-an385 Cortex-M3),
 * with the boot-specific additions the -sys reference config deliberately
 * omits:
 *
 *  1. cortex-m-rt DIRECT-ROUTING of the exception handlers: #define the
 *     FreeRTOS ARM_CM3 handler names to the cortex-m-rt vector-table symbol
 *     names, so port.c defines `SVCall`/`PendSV`/`SysTick` directly. The
 *     linker then overrides cortex-m-rt's weak defaults with these strong C
 *     symbols (PendSV/SVCall are `naked` context-switch asm — they MUST be the
 *     vector entries, not Rust-wrapped). This is why configCHECK_HANDLER_
 *     INSTALLATION stays 0 (we route via cortex-m-rt, not FreeRTOS's own
 *     vector install).
 *  2. A larger heap (the wz lwIP socket Inner ~12 KB + executor + the wz task
 *     stack all come from heap_4 via FreertosAllocator; mps2 has 4 MB SRAM).
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* (1) cortex-m-rt direct routing — must precede any use of the handler names. */
#define vPortSVCHandler      SVCall
#define xPortPendSVHandler   PendSV
#define xPortSysTickHandler  SysTick

/* ---- Hardware (QEMU mps2-an385, Cortex-M3) ---- */
#define configCPU_CLOCK_HZ                       ( ( unsigned long ) 25000000 )
#define configTICK_RATE_HZ                       ( ( TickType_t ) 1000 )

/* ---- Scheduling (see the -sys reference config for the cooperative-profile note) ---- */
#define configUSE_PREEMPTION                     1
#define configUSE_TIME_SLICING                   1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION  0
#define configUSE_TICKLESS_IDLE                  0
#define configMAX_PRIORITIES                     5
#define configMINIMAL_STACK_SIZE                 ( ( unsigned short ) 128 )
#define configMAX_TASK_NAME_LEN                  12
#define configTICK_TYPE_WIDTH_IN_BITS            TICK_TYPE_WIDTH_32_BITS
#define configIDLE_SHOULD_YIELD                  1
#define configUSE_TASK_NOTIFICATIONS             1
#define configUSE_MUTEXES                        1
#define configUSE_RECURSIVE_MUTEXES              0
#define configUSE_COUNTING_SEMAPHORES            0
#define configENABLE_BACKWARD_COMPATIBILITY      0
#define configSTACK_DEPTH_TYPE                   uint16_t

/* ---- Memory (heap_4) — generous for the lwIP socket + executor ---- */
#define configSUPPORT_STATIC_ALLOCATION          0
#define configSUPPORT_DYNAMIC_ALLOCATION         1
#define configTOTAL_HEAP_SIZE                    ( ( size_t ) ( 256 * 1024 ) )
#define configAPPLICATION_ALLOCATED_HEAP         0

/* ---- Software timers / co-routines / event groups: off (executor owns time) ---- */
#define configUSE_TIMERS                         0
#define configUSE_CO_ROUTINES                    0
#define configUSE_EVENT_GROUPS                   0
#define configUSE_STREAM_BUFFERS                 0
#define configUSE_QUEUE_SETS                     0

/* ---- Hooks + bring-up diagnostics (the deploy provides the hook bodies) ---- */
#define configUSE_IDLE_HOOK                      0
#define configUSE_TICK_HOOK                      0
#define configUSE_MALLOC_FAILED_HOOK             1
#define configCHECK_FOR_STACK_OVERFLOW           2

/* ---- Stats: off ---- */
#define configGENERATE_RUN_TIME_STATS            0
#define configUSE_TRACE_FACILITY                 0
#define configUSE_STATS_FORMATTING_FUNCTIONS     0

/* ---- Cortex-M3 (ARMv7-M) interrupt priorities (mps2-an385 NVIC = 3 prio bits) ---- */
#define configPRIO_BITS                          3
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY      7
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY 5
#define configKERNEL_INTERRUPT_PRIORITY \
    ( configLIBRARY_LOWEST_INTERRUPT_PRIORITY << ( 8 - configPRIO_BITS ) )
#define configMAX_SYSCALL_INTERRUPT_PRIORITY \
    ( configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << ( 8 - configPRIO_BITS ) )

/* Indirect-vs-direct: see (1) above — we direct-route via the #defines, so the
 * FreeRTOS-side install assert is disabled. */
#define configCHECK_HANDLER_INSTALLATION         0

/* ---- INCLUDE_* API surface ---- */
#define INCLUDE_vTaskDelay                       1
#define INCLUDE_vTaskDelayUntil                  1
#define INCLUDE_vTaskDelete                      1
#define INCLUDE_vTaskSuspend                     1
#define INCLUDE_xTaskGetSchedulerState           1
#define INCLUDE_xTaskGetCurrentTaskHandle        1
#define INCLUDE_uxTaskPriorityGet                0
#define INCLUDE_vTaskPrioritySet                 0

#define configASSERT( x )            \
    if( ( x ) == 0 )                 \
    {                                \
        taskDISABLE_INTERRUPTS();    \
        for( ; ; ) { }               \
    }

#endif /* FREERTOS_CONFIG_H */
