/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * wz_ext.h -- the C doors wz has and the upstream libraries do not.
 *
 * The drop-in headers declare upstream's functions only (docs/build-configuration.md,
 * decision C10): a program that includes a drop-in header and not this one is portable to
 * the upstream library. Every function of wz's own is `wz_ext_*` and declared here, so a
 * program that needs one says so by including this file, and the compiler tells it what is
 * not portable. scripts/lib/drop_in_header_gate.py holds both halves.
 *
 * Include the drop-in header of the library first; the declarations here use its types.
 */

#ifndef WZ_EXT_H
#define WZ_EXT_H

/* What an open of this config would ask of the operating system, as ONE
 * JSON object with the keys of the target-build manifest
 * (docs/target-build-contract.md T9):
 *
 *     {"requires": [...], "may_require": [...] or null, "unknown": [...]}
 *
 * requires is what every run of the config cannot go on without;
 * may_require is the rest a run may ask for, null when part of it has no
 * facility name, and unknown says why. The words are the manifest's
 * facility vocabulary. The config is read as z_open reads it, and is not
 * consumed. Part of the unstable surface: a library built without its
 * unstable API does not have it.
 *
 * Z_OK with the object, or the code z_open would refuse the config with,
 * the string then naming the reason. */
z_result_t wz_ext_config_device_requires(const z_loaned_config_t *config,
                                         z_owned_string_t *out_requirement);

/* A clock the program registers, which z_timestamp_new then stamps with in
 * place of the system clock: a disciplined hardware clock, or a time master
 * on the device's bus. Part of the unstable surface, and present only in a
 * build with the clock-source capability.
 *
 * The callback reads the time since the Unix epoch as whole seconds and the
 * nanoseconds within the second (below 1000000000). It returns 0 with both
 * written, or any other value when the clock cannot say what time it is: not
 * set, not yet synchronised, its bus silent. It is called from whichever
 * thread stamps, possibly several at once, and must be safe to call that way;
 * context must stay valid for as long as the source is registered. */
typedef int8_t wz_ext_clock_read_fn(void *context, uint64_t *secs,
                                    uint32_t *nanos);

/* Register a clock after those already registered: the first that can say
 * what time it is answers. If every registered clock is unable to, the library
 * knows no date, and z_timestamp_new fails; it does not fall back to the
 * system clock of a clock the program chose. out_handle receives the handle
 * wz_ext_clock_source_unregister takes and may be NULL.
 *
 * Z_OK; Z_ERR_NULL for a NULL callback; Z_ERR_OVERFLOW when the build's
 * CLOCK_SOURCES are all taken. */
z_result_t wz_ext_clock_source_register(wz_ext_clock_read_fn *read,
                                        void *context, uint32_t *out_handle);

/* Remove a clock registered earlier; the library then no longer calls the
 * callback. Z_ERR_INVALID for a handle that is not registered. */
z_result_t wz_ext_clock_source_unregister(uint32_t handle);

/* What the program tells the library about the registered clock. The library
 * cannot know whether the clock follows a reference; the program can. A build
 * whose clock-quality-stamping policy is trusted-only stamps nothing until the
 * program has reported WZ_EXT_CLOCK_SYNC_ACQUIRED. */
typedef uint8_t wz_ext_clock_event_t;
#define WZ_EXT_CLOCK_SYNC_ACQUIRED 0     /* it follows a reference */
#define WZ_EXT_CLOCK_SYNC_LOST 1         /* the reference is gone */
#define WZ_EXT_CLOCK_HOLDOVER_EXPIRED 2  /* the program's bound on running
                                            without a reference has passed */

/* Z_OK; Z_ERR_INVALID for another value. Reporting what is already so is not
 * an error. */
z_result_t wz_ext_clock_report(wz_ext_clock_event_t event);

/* The node's event log: a ring of fixed-size records that the library and the
 * program write events into and that a program reads back. An event is a
 * level, a source and up to EVENT_RECORD_ARGS integers (a build limit); it
 * carries no text, the format it is read with is a constant the reader holds,
 * keyed by the source. Part of the unstable surface, and present only in a
 * build with the event-ring capability.
 *
 * The log is one ring for the process. When it is full, the build's
 * event-ring-full policy says which event is given up: the oldest
 * (overwrite-oldest) or the new one (drop-newest). */

/* What a read found. */
#define WZ_EXT_EVENT_RECORD 0 /* an event */
#define WZ_EXT_EVENT_EMPTY 1  /* nothing newer than the cursor */
#define WZ_EXT_EVENT_LOST 2   /* events were overwritten before they were read;
                                 sequence is how many */

typedef struct wz_ext_event_t {
  uint8_t kind;      /* WZ_EXT_EVENT_RECORD, _EMPTY or _LOST */
  uint8_t level;     /* how serious, in the program's own scale */
  uint8_t arg_count; /* how many integers the event carries */
  uint8_t reserved;
  uint16_t source;   /* what said it, in the program's own numbering */
  uint16_t reserved2;
  uint64_t sequence; /* the event's number in the log; for _LOST, how many are
                        gone */
  uint64_t timestamp; /* an NTP64 word, 0 where the clock did not know the
                         date */
} wz_ext_event_t;

/* Write an event. args is arg_count integers (NULL when 0); the log keeps as
 * many as the build allows. The time is the clock's now: the clocks the
 * program registered, or the system clock.
 *
 * Z_OK; Z_ERR_OVERFLOW when a full log under drop-newest refused the event (it
 * is counted); Z_ERR_NULL for a NULL args with a count. */
z_result_t wz_ext_event_emit(uint8_t level, uint16_t source,
                             const uint64_t *args, size_t arg_count);

/* Read the event at *cursor, the number the program reads next (0 at the
 * start); it moves past the event read, or past the events that were lost. out
 * receives the result, and the event's integers go to args, up to
 * args_capacity of them (args may be NULL when that is 0). Any number of
 * programs read the same log, each with a cursor of its own. Z_OK;
 * Z_ERR_NULL for a NULL cursor or out. */
z_result_t wz_ext_event_read(uint64_t *cursor, wz_ext_event_t *out,
                             uint64_t *args, size_t args_capacity);

/* Say that every event before sequence number upto has been read and may be
 * overwritten. Only forward. Under overwrite-oldest nothing waits for it; under
 * drop-newest it is what makes room. */
z_result_t wz_ext_event_release(uint64_t upto);

/* How many events a full log refused under drop-newest. */
uint32_t wz_ext_event_dropped(void);

/* The node's supervisor: checkpoints a program feeds, each with a deadline, and
 * a hook that runs once for a checkpoint that missed its deadline. Part of the
 * unstable surface, and present only in a build with the supervision
 * capability. How many checkpoints there are is a build limit
 * (SUPERVISION_CHECKPOINTS), numbered from 0.
 *
 * A program that must keep making progress starts a checkpoint with a timeout
 * and feeds it on every pass, and calls wz_ext_supervision_check on its own
 * cadence: the library holds no thread and no timer. The supervisor is healthy
 * only while every checkpoint that is supervised has been fed in time, so a
 * node that feeds a hardware watchdog feeds it when wz_ext_supervision_healthy
 * is 1, and from nowhere else. Time is milliseconds on the monotonic clock. */

/* The program's expiry hook. It runs on the thread that called
 * wz_ext_supervision_check, with no lock of the library held, so it may call
 * any of these functions. */
typedef void wz_ext_supervision_hook_fn(void *context, uint8_t checkpoint);

/* The state of a checkpoint. */
#define WZ_EXT_SUPERVISION_DISARMED 0 /* not supervised */
#define WZ_EXT_SUPERVISION_ARMED 1    /* supervised, and fed in time */
#define WZ_EXT_SUPERVISION_EXPIRING 2 /* its hook is running */
#define WZ_EXT_SUPERVISION_EXPIRED 3  /* its hook has run */
#define WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT 255

/* Set the hook, or clear it with NULL. With none set, an expired checkpoint is
 * still marked expired and makes the supervisor unhealthy. The hook must be safe
 * to call from the thread that calls wz_ext_supervision_check, and context must
 * stay valid, for as long as it is set. Z_OK. */
z_result_t wz_ext_supervision_set_hook(wz_ext_supervision_hook_fn *hook,
                                       void *context);

/* Begin supervising a checkpoint, with a deadline timeout_ms after now and
 * after each feed. A checkpoint already supervised is left as it is. Z_OK;
 * Z_ERR_INVALID for a checkpoint the build does not have, or a timeout of 0 or
 * past 2147483647. */
z_result_t wz_ext_supervision_start(uint8_t checkpoint, uint32_t timeout_ms);

/* The program made progress: start the checkpoint's deadline again. A
 * checkpoint that is not armed ignores it, so a feed after an expiry does not
 * hide it (the build's supervision-after-expiry policy can have such a feed
 * supervise the checkpoint again). Z_OK; Z_ERR_INVALID for a checkpoint the
 * build does not have. */
z_result_t wz_ext_supervision_feed(uint8_t checkpoint);

/* Stop supervising a checkpoint. Z_OK; Z_ERR_GENERIC when its hook is running:
 * it does not stop until the hook returns; Z_ERR_INVALID for a checkpoint the
 * build does not have. */
z_result_t wz_ext_supervision_stop(uint8_t checkpoint);

/* Look at every supervised checkpoint now and run the hook once for each whose
 * deadline has passed. Z_OK. */
z_result_t wz_ext_supervision_check(void);

/* 1 when at least one checkpoint is supervised and every supervised one is
 * armed, 0 otherwise. Nothing under watch is not healthy. */
uint8_t wz_ext_supervision_healthy(void);

/* The state of a checkpoint, one of the values above. */
uint8_t wz_ext_supervision_state(uint8_t checkpoint);

/* The node's resource snapshot: a fixed-layout, versioned record of the CPU
 * use, the heap and the tasks the platform reports, and of how the messages the
 * session received were spaced. Part of the unstable surface, and present only
 * in a build with the resource-snapshot capability.
 *
 * The platform is the program's: it sets a source that answers what it can, and
 * a part it cannot answer is marked unavailable in the record, not read as zero.
 * The library holds no thread and no timer: the program calls
 * wz_ext_snapshot_poll on its own cadence, which takes a snapshot when the
 * build's period (SNAPSHOT_PERIOD_MS) has passed since the last, and
 * wz_ext_snapshot_read copies the latest out as bytes. */

/* What the source writes: the readings it has, and which of them it has. A
 * field whose bit in available is clear is not read, whatever the source left in
 * it. */
#define WZ_EXT_SNAPSHOT_HAS_CPU 1
#define WZ_EXT_SNAPSHOT_HAS_HEAP 2
#define WZ_EXT_SNAPSHOT_HAS_TASKS 4

typedef struct wz_ext_resource_reading_t {
  uint8_t available;     /* the WZ_EXT_SNAPSHOT_HAS_* bits */
  uint8_t reserved;
  uint16_t cpu_permille; /* busy share since the last reading, in thousandths */
  uint16_t tasks;        /* how many tasks the node runs */
  uint16_t reserved2;
  uint64_t heap_in_use;     /* bytes on the heap in use now */
  uint64_t heap_high_water; /* the most bytes there have been in use */
} wz_ext_resource_reading_t;

/* The program's source: fills out and returns 0, or returns anything else when
 * it cannot answer at all, which takes the snapshot with no part available. It
 * runs on the thread that called wz_ext_snapshot_poll, with no lock of the
 * library held, so it may call any of these functions. */
typedef int8_t wz_ext_snapshot_source_fn(void *context,
                                         wz_ext_resource_reading_t *out);

/* Set the source, or clear it with NULL. With none set, a snapshot is still
 * taken, with the message counts and no part of the platform's. The source must
 * be safe to call from the thread that calls wz_ext_snapshot_poll, and context
 * must stay valid, for as long as it is set. Z_OK. */
z_result_t wz_ext_snapshot_set_source(wz_ext_snapshot_source_fn *read,
                                      void *context);

/* Take a snapshot if the build's period has passed since the last, of the
 * session's received messages and whatever the source answers. 1 when one was
 * taken, 0 when none was due, Z_ERR_NULL for a null or spent session. The first
 * call takes one. */
z_result_t wz_ext_snapshot_poll(const z_loaned_session_t *session);

/* How many bytes wz_ext_snapshot_read writes: the size of this build's record,
 * which grows with SNAPSHOT_HISTOGRAM_BUCKETS. */
size_t wz_ext_snapshot_size(void);

/* Copy the latest snapshot into out, which has room for capacity bytes, and
 * write its length to length. The record is little-endian and starts with its
 * own layout version and size, so a reader of an older build can tell a newer
 * one. Z_OK; Z_ERR_GENERIC before the first snapshot; Z_ERR_OVERFLOW when
 * capacity is less than wz_ext_snapshot_size; Z_ERR_NULL for a null out or
 * length. */
z_result_t wz_ext_snapshot_read(uint8_t *out, size_t capacity, size_t *length);

#endif /* WZ_EXT_H */
