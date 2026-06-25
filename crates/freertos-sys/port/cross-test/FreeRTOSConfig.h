/*
 * SPDX-License-Identifier: MIT
 *
 * Reference FreeRTOSConfig.h for the watching-zenoh cooperative single-task
 * profile on QEMU mps2-an385 (ARM Cortex-M3 / ARMv7-M, thumbv7m-none-eabi).
 *
 * This is the DEFAULT cross-compile config baked into freertos-sys so the
 * crate (and Layer G) can cross-compile the kernel standalone. A deploy crate
 * MAY override it by pointing WZ_FREERTOS_CONFIG at its own include directory
 * (mirrors lwip-sys's WZ_LWIP_PORT). Adapted from FreeRTOS-Kernel V11.1.0
 * examples/template_configuration/FreeRTOSConfig.h.
 *
 * Profile note: the wz runtime drives its own cooperative async executor
 * inside ONE FreeRTOS task (= zenoh-pico Z_FEATURE_MULTI_THREAD=0 single-thread
 * mode). Software timers, co-routines, and the MPU/TrustZone/FPU machinery are
 * disabled — the executor owns timing (CoopTime) and there is one task.
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* ---- Hardware (QEMU mps2-an385, Cortex-M3) ---- */
#define configCPU_CLOCK_HZ                       ( ( unsigned long ) 25000000 )
#define configTICK_RATE_HZ                       ( ( TickType_t ) 1000 )

/* ---- Scheduling ----
 * NB: "cooperative single-task profile" refers to the wz ASYNC EXECUTOR model
 * (one FreeRTOS task hosts wz-runtime-coop's run_until_idle, = zenoh-pico
 * Z_FEATURE_MULTI_THREAD=0) — NOT the FreeRTOS scheduler mode. The scheduler
 * stays standard preemptive (idle task + the one wz task); with a single
 * application task preemption/time-slicing are functionally inert. */
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

/* ---- Memory (heap_4) ---- */
#define configSUPPORT_STATIC_ALLOCATION          0
#define configSUPPORT_DYNAMIC_ALLOCATION         1
#define configTOTAL_HEAP_SIZE                    ( ( size_t ) ( 32 * 1024 ) )
#define configAPPLICATION_ALLOCATED_HEAP         0

/* ---- Software timers / co-routines / event groups: off (executor owns time) ---- */
#define configUSE_TIMERS                         0
#define configUSE_CO_ROUTINES                    0
#define configUSE_EVENT_GROUPS                   0
#define configUSE_STREAM_BUFFERS                 0
#define configUSE_QUEUE_SETS                     0

/* ---- Hooks + bring-up diagnostics ----
 * Stack-overflow checking + malloc-failed hook are ON: they are the two
 * diagnostics that most help bring up a NEW RTOS port (Round 3 QEMU). The deploy
 * binary provides vApplicationStackOverflowHook + vApplicationMallocFailedHook
 * (undefined externs in this -sys static lib, resolved at the deploy's final
 * link). idle/tick hooks stay off (no use in the single-task profile). */
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

/* The wz cooperative profile routes the SVC/PendSV/SysTick exceptions to the
 * port handlers via the cortex-m-rt vector table (indirect routing), so the
 * direct-installation assert is disabled. */
#define configCHECK_HANDLER_INSTALLATION         0

/* ---- INCLUDE_* API surface used by the cooperative single-task profile ---- */
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
