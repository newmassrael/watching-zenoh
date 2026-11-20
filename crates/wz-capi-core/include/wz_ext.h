/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * wz_ext.h -- the C doors wz has and the upstream libraries do not.
 *
 * The drop-in headers declare upstream's functions only, drop-in and extension being
 * separate namespaces: a program that includes a drop-in header and not this one is
 * portable to the upstream library. Every function of wz's own is `wz_ext_*` and declared
 * here, so a program that needs one says so by including this file, and the compiler tells
 * it what is not portable. scripts/lib/drop_in_header_gate.py holds both halves.
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

/* The policies of the session z_open opens from this config, stated from
 * code. The open composes them, lowest first: the build defaults, the
 * profile (wz_ext_config_profile's, else the document's), the document's
 * wz/policies, then wz_ext_config_policy's statements. The first two doors
 * are in every build, wz_ext_config_document in a build with the
 * config-document capability (it links a JSON5 reader); a build whose
 * domain of a policy holds one value refuses every other value of it.
 *
 * Each call is checked at once against the build, as the open will compose
 * it: a policy, value or profile the build does not have, a value the
 * build's domain leaves out, a policy only the build decides, and a document
 * whose wz member has a refused shape answer _Z_ERR_CONFIG_INVALID_VALUE
 * and leave the config as it was. A null argument answers _Z_ERR_NULL.
 *
 * wz_ext_config_policy states that `policy` takes `value` (both by the
 * declaration's ids); a second statement of the policy replaces the first.
 * wz_ext_config_profile names the profile the session starts from, in place
 * of the one the document names. wz_ext_config_document hands the config a
 * zenoh JSON5 document of which only the wz member is read, so the document
 * a zenoh-c program opens with configures these policies alike; a second
 * call replaces the first. In a build with the shared-key-ids capability the
 * member's wz/key-ids states the key ids every node shares (dictionary, a
 * list of { id, key }, and links, a list of { locator, form }), under what
 * wz_ext_config_key_ids and wz_ext_config_key_wire_form_for state; a build
 * without it refuses wz/key-ids, and a refused part of it refuses the
 * document, as a refused policy does. */
z_result_t wz_ext_config_policy(z_loaned_config_t *config, const char *policy,
                                const char *value);
z_result_t wz_ext_config_profile(z_loaned_config_t *config,
                                 const char *profile);
z_result_t wz_ext_config_document(z_loaned_config_t *config,
                                  const char *json5);

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
 * whose clock-quality-stamping policy is trusted-only stamps no data until the
 * program has reported WZ_EXT_CLOCK_SYNC_ACQUIRED: an advanced publisher, every
 * sample of which carries a time, refuses its put and delete until then, and
 * nothing is sent. z_timestamp_new, a program reading the clock, is given its
 * time whatever its standing. */
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

/* What the library itself writes into the log. A program numbers its own
 * sources and levels; the library's events carry level 255 and a source from
 * 0xFF00 up, so a program keeps its sources below WZ_EXT_EVENT_SOURCE_LIBRARY
 * and a reader that filters by level keeps 255 to see what the node says about
 * itself. A source is assigned once and never reused; the integers of each are
 * written beside it. */
#define WZ_EXT_EVENT_LEVEL_LIBRARY 255
#define WZ_EXT_EVENT_SOURCE_LIBRARY 0xFF00
/* A supervised checkpoint missed its deadline (a build with the supervision
 * capability too). One integer: the checkpoint's number. */
#define WZ_EXT_EVENT_SOURCE_SUPERVISION_EXPIRED 0xFF00
/* A listener of a tls/ link took a connection and ended it without a stream
 * (the cooperative engine with the secure channel). Two integers: why, and the
 * channel's own code. This is how a program sees that the arena or the key
 * store had no room for a handshake, which a peer sees only as a closed
 * connection. */
#define WZ_EXT_EVENT_SOURCE_TLS_HANDSHAKE_DROPPED 0xFF01
#define WZ_EXT_EVENT_TLS_DROP_STALLED 0 /* a peer that stalled past the accept
                                           budget; the code is 0 */
#define WZ_EXT_EVENT_TLS_DROP_NO_ROOM 1 /* the arena or the key store had no
                                           room; the code is the channel's */
#define WZ_EXT_EVENT_TLS_DROP_OTHER 2   /* any other failure, or a peer the
                                           policy refused; the code is the
                                           channel's, 0 where it has none */
/* An instance key reported the samples it dropped (a build with the
 * instance-key capability too; see wz_ext_instance_keyer_new). Three integers:
 * why the latest of them was dropped, which key field, and how many were
 * dropped since the last report. */
#define WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED 0xFF02
#define WZ_EXT_EVENT_INSTANCE_KEY_UNDECODABLE 0 /* the payload is not a message
                                                   of the schema */
#define WZ_EXT_EVENT_INSTANCE_KEY_ABSENT 1      /* a key field with presence is
                                                   absent */
#define WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED 2  /* a key value is in no list */

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

/* The sending side of a declared segment profile: one message of the program's
 * own cut into pieces, each an ordinary sample on the message's key whose
 * payload is a header the profile describes (where the chunk sits, how large
 * the whole is, which transfer it belongs to, a check value) and the chunk.
 * Part of the unstable surface, and present only in a build with the
 * segment-sender capability. The pieces are written by the same field layout
 * and CRC rule a reader of that profile joins them by.
 *
 * WHO WRITES WHICH FIELD. A field with "equals" holds that value; the transfer
 * field is the sender's number; the total and offset fields are the message's
 * length and where each chunk starts; the crc field is the CRC the profile's
 * "cover" list describes. Every other field is the program's, stated once in
 * values_json as a JSON object keyed by field name ({"origin": 4660}, or
 * "0x1234" as a string). Leaving one out, or stating one the profile or the
 * mechanism writes, is refused.
 *
 * THE TRANSFER NUMBER. The first message carries first_transfer, each after it
 * the next value. A message refused before any piece consumes no number; a
 * message whose first piece went out has used its number, even when a later
 * piece did not. After the largest value the field holds the next message is
 * refused, unless the sender restarts, which goes back to first_transfer.
 *
 * OWNERSHIP. A sender is owned by the program from wz_ext_segment_sender_new
 * until wz_ext_segment_sender_drop, which leaves the null state; a second drop
 * does nothing. The doors that use it take the loan. A refusal string, when
 * one is written, is the program's to drop with z_string_drop.
 *
 * THREADS. One sender may be called from several threads: a message's pieces
 * are written and handed on under one lock, so two messages on one sender never
 * interleave. A split callback runs on the calling thread, inside that lock, so
 * it must not call its own sender. */

typedef uint8_t wz_ext_segment_rollover_t;
#define WZ_EXT_SEGMENT_ROLLOVER_REFUSE 0  /* refuse the next message */
#define WZ_EXT_SEGMENT_ROLLOVER_RESTART 1 /* go back to first_transfer */

typedef struct wz_ext_owned_segment_sender_t {
  void *_handle;
} wz_ext_owned_segment_sender_t;
typedef struct wz_ext_loaned_segment_sender_t {
  void *_handle;
} wz_ext_loaned_segment_sender_t;
typedef struct wz_ext_moved_segment_sender_t {
  wz_ext_owned_segment_sender_t _this;
} wz_ext_moved_segment_sender_t;

/* How far one put or split went. */
typedef struct wz_ext_segment_result_t {
  uint64_t transfer; /* the number the pieces carried; 0 when refused */
  size_t pieces;     /* how many pieces the message was cut into; 0 when
                        refused */
  size_t sent;       /* how many pieces went out */
} wz_ext_segment_result_t;

/* The options of a put. timestamp is a const z_timestamp_t *, BORROWED for the
 * call, that every piece carries; NULL for none. */
typedef struct wz_ext_segment_put_options_t {
  const void *timestamp;
} wz_ext_segment_put_options_t;

/* What a split hands each piece to. piece is valid only during the call.
 * Anything but Z_OK stops the split, which returns it. */
typedef z_result_t wz_ext_segment_piece_fn(void *context, const uint8_t *piece,
                                           size_t len);

/* A sender for the profile profile_json describes, with the program's fields in
 * values_json, whose first message carries first_transfer. this_ holds the null
 * state on every error. refusal may be NULL; when it is not, it holds the null
 * state on success and, on _Z_ERR_CONFIG_INVALID_VALUE (-89), the reason,
 * beginning "profile" or "values" and naming the place.
 *
 * Z_OK; Z_ERR_NULL for a NULL this_, profile_json or values_json; Z_EINVAL
 * (-75) for text that is not UTF-8 or an unknown rollover;
 * _Z_ERR_CONFIG_INVALID_VALUE (-89) for a profile or values text that is
 * refused. */
z_result_t wz_ext_segment_sender_new(wz_ext_owned_segment_sender_t *this_,
                                     const char *profile_json,
                                     const char *values_json,
                                     uint64_t first_transfer,
                                     wz_ext_segment_rollover_t rollover,
                                     z_owned_string_t *refusal);

/* Fill in the default put options: no timestamp. */
void wz_ext_segment_put_options_default(wz_ext_segment_put_options_t *this_);

/* Cut message into chunks of chunk_bytes and put each piece on publisher, in
 * order (options may be NULL). result and refusal may be NULL.
 *
 * Z_OK when every piece was put; Z_EINVAL (-75) when the message was refused
 * before any piece (empty, longer than the profile admits, a chunk size of 0, a
 * value that does not fit its field, the number spent), refusal saying why and
 * no number used; the failing put's code, after result->sent pieces, when one
 * failed (the number is used); Z_ERR_NULL for a NULL or dropped sender, a NULL
 * publisher, or a NULL message with a length. */
z_result_t wz_ext_segment_sender_put(
    const wz_ext_loaned_segment_sender_t *this_,
    const z_loaned_publisher_t *publisher, const uint8_t *message, size_t len,
    size_t chunk_bytes, const wz_ext_segment_put_options_t *options,
    wz_ext_segment_result_t *result, z_owned_string_t *refusal);

/* As wz_ext_segment_sender_put, but each piece, header and chunk, is handed to
 * emit with context instead of put: for a program that sends the pieces some
 * other way, as the replies of a query for instance. Returns what emit returned
 * when it stopped the split; Z_ERR_NULL for a NULL emit. */
z_result_t wz_ext_segment_sender_split(
    const wz_ext_loaned_segment_sender_t *this_, const uint8_t *message,
    size_t len, size_t chunk_bytes, wz_ext_segment_piece_fn *emit,
    void *context, wz_ext_segment_result_t *result, z_owned_string_t *refusal);

/* The number the next message carries. false, and nothing written, when the
 * largest was sent and the sender does not restart, or for a NULL argument or
 * a dropped sender. */
bool wz_ext_segment_sender_next(const wz_ext_loaned_segment_sender_t *this_,
                                uint64_t *out);

/* Make value the number the next message carries. A value past the transfer
 * field's width is refused by the next message, as a first number is. Z_OK;
 * Z_ERR_NULL for a NULL or dropped sender. */
z_result_t wz_ext_segment_sender_set(const wz_ext_loaned_segment_sender_t *this_,
                                     uint64_t value);

const wz_ext_loaned_segment_sender_t *wz_ext_segment_sender_loan(
    const wz_ext_owned_segment_sender_t *this_);
wz_ext_moved_segment_sender_t *wz_ext_segment_sender_move(
    wz_ext_owned_segment_sender_t *this_);
void wz_ext_segment_sender_drop(wz_ext_moved_segment_sender_t *this_);
void wz_ext_internal_segment_sender_null(wz_ext_owned_segment_sender_t *this_);
bool wz_ext_internal_segment_sender_check(
    const wz_ext_owned_segment_sender_t *this_);

/* Reception supervision per stream: whether each periodic stream a program
 * receives keeps arriving. Part of the unstable surface, and present only in a
 * build with the e2e-supervision capability.
 *
 * A stream is one message, of one instance, from one sender. The program adds
 * each with its period and a factor, and its deadline is their product: a
 * stream not received for longer than that is LOST. A loss is told once to the
 * program's callback (an edge, not a level), and the stream's error count and
 * the node's each go up by one, stopping at 255.
 *
 * WHEN ANYTHING IS JUDGED. Nothing is judged until start_delay_ms has passed
 * since the first poll that had a clock, and then only while the program's
 * condition holds (wz_ext_stream_supervisor_set_condition; it holds until the
 * program says otherwise). Each time the two come to hold together, every
 * stream that can time out has its deadline counted again from that poll and
 * every error count is reset to 0, so a stream that never arrived is lost one
 * deadline after the activation. An awaited stream can time out from the
 * start; one that is not is supervised from its first reception. A poll
 * without a clock judges nothing and the next poll with one activates again.
 *
 * ABSENT SENDERS. A sender the program marks absent has none of its streams
 * judged, and a loss one was in is withdrawn without being told, until it is
 * marked present again, which counts their deadlines from that moment. The
 * sender is a number of the program's own, given with each stream.
 *
 * STORAGE. The table is the program's: an array of wz_ext_stream_slot_t, one
 * per stream, and under the build's e2e-supervision-notify policy last-value a
 * byte area of one cell per slot, where the last payload of each stream is
 * kept for the loss to hand back. The supervisor writes both when it is made
 * and owns them until it is dropped. How many streams one supervisor holds is
 * at most the build's E2E_SUPERVISED_STREAMS.
 *
 * TIME is milliseconds in 32 bits that wrap: the program's clock, given at
 * creation, or the library's monotonic clock when it gives none.
 *
 * THE POLL is the program's to call on its own cadence, which is how a
 * single-threaded program and the cooperative engine drive it; a build with
 * tasks can have the library poll on a task of its own.
 *
 * THREADS. One supervisor may be called from several threads, each door under
 * its lock. The clock and the callback run inside that lock on the thread that
 * polls, so neither may call a door of its own supervisor. */

/* One row of the program's table, owned by the supervisor while it lives. */
typedef struct wz_ext_stream_slot_t {
  uint32_t _opaque[5];
} wz_ext_stream_slot_t;

/* The program's clock: writes the milliseconds of a monotonic source and
 * returns 0, or returns anything else when it cannot say what time it is. */
typedef int8_t wz_ext_stream_clock_fn(void *context, uint32_t *now_ms);

/* One loss, as the callback reads it: 32 bytes on a 64-bit target, 24 on a
 * 32-bit one. It and the value it points to are valid only for the call. */
typedef struct wz_ext_stream_loss_t {
  uint32_t stream;      /* the number wz_ext_stream_supervisor_add gave it */
  uint32_t sender;      /* the sender it was added with */
  uint8_t errors;       /* the stream's error count, this loss included */
  uint8_t node_errors;  /* the node's error count, this loss included */
  uint16_t reserved;
  uint32_t reserved2;
  const uint8_t *value; /* under last-value the stream's last payload; NULL
                           under status-only or when none was kept */
  size_t value_len;
} wz_ext_stream_loss_t;

typedef void wz_ext_stream_loss_fn(void *context,
                                   const wz_ext_stream_loss_t *loss);

/* Where the two gates stand. */
#define WZ_EXT_STREAM_UNCLOCKED 0 /* no poll has had a clock */
#define WZ_EXT_STREAM_DELAYING 1  /* the start delay runs */
#define WZ_EXT_STREAM_INACTIVE 2  /* the condition does not hold */
#define WZ_EXT_STREAM_ACTIVE 3    /* every poll judges the streams */
#define WZ_EXT_STREAM_NO_SUPERVISOR 255

/* What a loss carries: the build's e2e-supervision-notify policy. */
#define WZ_EXT_STREAM_NOTIFY_STATUS_ONLY 0
#define WZ_EXT_STREAM_NOTIFY_LAST_VALUE 1

typedef struct wz_ext_owned_stream_supervisor_t {
  void *_handle;
} wz_ext_owned_stream_supervisor_t;
typedef struct wz_ext_loaned_stream_supervisor_t {
  void *_handle;
} wz_ext_loaned_stream_supervisor_t;
typedef struct wz_ext_moved_stream_supervisor_t {
  wz_ext_owned_stream_supervisor_t _this;
} wz_ext_moved_stream_supervisor_t;

/* A supervisor of no stream yet over slot_count rows at slots and, under
 * last-value, slot_count cells of value_cell bytes at values (not read under
 * status-only, where it may be NULL). clock may be NULL. this_ holds the null
 * state on every error.
 *
 * Z_OK; Z_ERR_NULL for a NULL this_ or slots, or a NULL values under
 * last-value; Z_ERR_INVALID for a slot_count of 0 or past 2^32 - 1, a start
 * delay past 2147483647, or under last-value a value_cell of 0. */
z_result_t wz_ext_stream_supervisor_new(
    wz_ext_owned_stream_supervisor_t *this_, wz_ext_stream_slot_t *slots,
    size_t slot_count, uint8_t *values, size_t value_cell,
    uint32_t start_delay_ms, wz_ext_stream_clock_fn *clock,
    void *clock_context);

/* Supervise a stream of period_ms that may miss factor periods, from sender,
 * and write its number to out_stream (which may be NULL). An awaited stream can
 * time out before its first reception. A stream of a sender marked absent is
 * absent with it.
 *
 * Z_OK; Z_ERR_NULL for a NULL or dropped supervisor; Z_ERR_INVALID for a
 * period or factor of 0, or a deadline past 2147483646 ms; Z_ERR_OVERFLOW when
 * the table is full. */
z_result_t wz_ext_stream_supervisor_add(
    const wz_ext_loaned_stream_supervisor_t *this_, uint32_t period_ms,
    uint16_t factor, uint32_t sender, bool awaited, uint32_t *out_stream);

/* The stream was received now, carrying payload (NULL with 0 for none), which
 * is kept under last-value. A loss it was in is over.
 *
 * Z_OK; Z_ERR_NULL for a NULL or dropped supervisor, or a NULL payload with a
 * length; Z_ERR_INVALID for a stream there is none of; Z_ERR_OVERFLOW under
 * last-value for a payload longer than the cell: the reception counts, the
 * value is not kept. */
z_result_t wz_ext_stream_supervisor_received(
    const wz_ext_loaned_stream_supervisor_t *this_, uint32_t stream,
    const uint8_t *payload, size_t len);

/* Whether the program's condition holds. Z_OK; Z_ERR_NULL for a NULL or
 * dropped supervisor. */
z_result_t wz_ext_stream_supervisor_set_condition(
    const wz_ext_loaned_stream_supervisor_t *this_, bool holds);

/* Mark a sender present or absent. The error counts are left as they are.
 * Z_OK, also when it already was; Z_ERR_NULL for a NULL or dropped supervisor;
 * Z_ERR_INVALID when no stream was added with that sender. */
z_result_t wz_ext_stream_supervisor_set_sender_present(
    const wz_ext_loaned_stream_supervisor_t *this_, uint32_t sender,
    bool present);

/* Set the callback, or clear it with NULL; a loss is counted either way. The
 * callback must be safe to call from the thread that polls, and context must
 * stay valid, for as long as it is set. Z_OK; Z_ERR_NULL for a NULL or dropped
 * supervisor. */
z_result_t wz_ext_stream_supervisor_set_callback(
    const wz_ext_loaned_stream_supervisor_t *this_, wz_ext_stream_loss_fn *call,
    void *context);

/* Look at every stream now and tell the callback once for each newly lost;
 * out_told (which may be NULL) receives how many. Z_OK; Z_ERR_NULL for a NULL
 * or dropped supervisor. */
z_result_t wz_ext_stream_supervisor_poll(
    const wz_ext_loaned_stream_supervisor_t *this_, size_t *out_told);

/* The stream's error count. Z_OK; Z_ERR_NULL for a NULL or dropped supervisor
 * or a NULL out; Z_ERR_INVALID for a stream there is none of. */
z_result_t wz_ext_stream_supervisor_stream_errors(
    const wz_ext_loaned_stream_supervisor_t *this_, uint32_t stream,
    uint8_t *out);

/* The node's error count since the last activation; 0 for a NULL supervisor. */
uint8_t wz_ext_stream_supervisor_node_errors(
    const wz_ext_loaned_stream_supervisor_t *this_);

/* One of WZ_EXT_STREAM_UNCLOCKED, _DELAYING, _INACTIVE, _ACTIVE, or
 * WZ_EXT_STREAM_NO_SUPERVISOR. */
uint8_t wz_ext_stream_supervisor_phase(
    const wz_ext_loaned_stream_supervisor_t *this_);

/* WZ_EXT_STREAM_NOTIFY_STATUS_ONLY or _LAST_VALUE, or
 * WZ_EXT_STREAM_NO_SUPERVISOR. */
uint8_t wz_ext_stream_supervisor_notify(
    const wz_ext_loaned_stream_supervisor_t *this_);

/* The library polls every period_ms on a task of its own until stopped or
 * dropped; the callback then runs on that task. Z_OK; Z_ERR_NULL for a NULL or
 * dropped supervisor; Z_ERR_INVALID for a period of 0 or a task already
 * running; Z_ERR_GENERIC when the host gave no thread. Stopping waits for the
 * task, and is refused with Z_ERR_GENERIC from the task itself. Declared in the
 * multi-threaded arm only, as the tasks of the drop-in are. */
#if defined(Z_FEATURE_MULTI_THREAD) && Z_FEATURE_MULTI_THREAD == 1
z_result_t wz_ext_stream_supervisor_start_task(
    const wz_ext_loaned_stream_supervisor_t *this_, uint32_t period_ms);
z_result_t wz_ext_stream_supervisor_stop_task(
    const wz_ext_loaned_stream_supervisor_t *this_);
#endif

const wz_ext_loaned_stream_supervisor_t *wz_ext_stream_supervisor_loan(
    const wz_ext_owned_stream_supervisor_t *this_);
wz_ext_moved_stream_supervisor_t *wz_ext_stream_supervisor_move(
    wz_ext_owned_stream_supervisor_t *this_);
/* Stops the task first; the storage is the program's again once it returns.
 * Not from the callback or the clock. */
void wz_ext_stream_supervisor_drop(wz_ext_moved_stream_supervisor_t *this_);
void wz_ext_internal_stream_supervisor_null(
    wz_ext_owned_stream_supervisor_t *this_);
bool wz_ext_internal_stream_supervisor_check(
    const wz_ext_owned_stream_supervisor_t *this_);

/* End-to-end protection of the program's payload: a header in front of it
 * that lets a receiver judge whether the frame is the one its sender built
 * (a CRC, an identifier, a length) and whether it is the next one (a
 * counter). The header is described by a PROFILE the program hands over as
 * JSON text, with the rules a receiver judges by; the library holds no
 * deployment's layout or constants. Part of the unstable surface.
 *
 * THE SENDER (e2e-sender capability) protects a payload under the profile and
 * the program's header values, which are fixed when it is made: every field
 * but the CRC, the length and the counter, in the values text the profile
 * describes, and "@address" for the fields and parts the profile derives from
 * the node's address. It keeps a counter for each stream it sends on (the
 * instances of one message); a frame that is built carries the stream's next
 * value, a refused one consumes none. With crc_cache a stream keeps its last
 * frame, and protecting an unchanged payload again gives the same bytes
 * without the full CRC computation.
 *
 * THE RECEIVER (e2e-receiver capability) judges each frame it is handed in the
 * state it keeps per stream, in storage it allocates once when it is made, and
 * writes a verdict; the payload is reported whatever the verdict, and whether
 * a sample reaches the application is the program's choice. Its streams are
 * named by the program (one per message or instance), or, with the
 * e2e-sender-demux capability, kept one per sender, chosen by the sender
 * identity of the profile's message cell: slots taken in arrival order by
 * intact frames, or bound to a list of senders. A frame of a sender no slot
 * holds is judged in no stream and counted.
 *
 * OWNERSHIP AND THREADS. As for the segment sender: owned from *_new until
 * *_drop, which leaves the null state; the doors take the loan; a refusal
 * string is the program's to drop. One handle may be called from several
 * threads. */

typedef uint8_t wz_ext_e2e_rollover_t;
#define WZ_EXT_E2E_ROLLOVER_REFUSE 0 /* refuse a stream's next frame */
#define WZ_EXT_E2E_ROLLOVER_WRAP 1   /* count on from zero */

typedef struct wz_ext_owned_e2e_sender_t {
  void *_handle;
} wz_ext_owned_e2e_sender_t;
typedef struct wz_ext_loaned_e2e_sender_t {
  void *_handle;
} wz_ext_loaned_e2e_sender_t;
typedef struct wz_ext_moved_e2e_sender_t {
  wz_ext_owned_e2e_sender_t _this;
} wz_ext_moved_e2e_sender_t;

typedef struct wz_ext_e2e_sender_options_t {
  uint64_t first_counter; /* the first frame of every stream carries it */
  size_t streams;         /* how many streams, at least 1 */
  wz_ext_e2e_rollover_t rollover; /* WZ_EXT_E2E_ROLLOVER_* */
  bool crc_cache;         /* keep each stream's last frame */
} wz_ext_e2e_sender_options_t;

/* One stream, a first counter of 0, refuse after the largest, no cache. */
void wz_ext_e2e_sender_options_default(wz_ext_e2e_sender_options_t *this_);

/* A sender for profile_json with the fixed header values values_json, made as
 * options says (NULL: the defaults). this_ holds the null state on every
 * error; refusal may be NULL and, on _Z_ERR_CONFIG_INVALID_VALUE (-89), holds
 * the reason, beginning "profile" or "values" and naming the place.
 *
 * Z_OK; Z_ERR_NULL for a NULL this_, profile_json or values_json; Z_EINVAL
 * (-75) for text that is not UTF-8 or an unknown rollover;
 * _Z_ERR_CONFIG_INVALID_VALUE for a profile, values text or option refused (no
 * stream, a first counter the counter field cannot hold, values that state
 * the counter or leave a field out). */
z_result_t wz_ext_e2e_sender_new(wz_ext_owned_e2e_sender_t *this_,
                                 const char *profile_json,
                                 const char *values_json,
                                 const wz_ext_e2e_sender_options_t *options,
                                 z_owned_string_t *refusal);

/* The size of the frame that protects payload_len bytes. Z_OK; Z_ERR_NULL. */
z_result_t wz_ext_e2e_sender_frame_size(
    const wz_ext_loaned_e2e_sender_t *this_, size_t payload_len, size_t *out);

/* Protect payload on stream: the frame written to out (room for capacity
 * bytes), its length to written, the counter it carries to counter (may be
 * NULL). Z_OK; Z_ERR_OVERFLOW (-74) when capacity is less than the frame;
 * Z_EINVAL (-75) when the frame is refused (no such stream, the stream sent its
 * largest value and does not wrap, a payload longer than the length field
 * describes), refusal saying why; Z_ERR_NULL for a NULL sender, out or
 * written, or a NULL payload with a length. Anything but Z_OK writes nothing
 * to out and consumes no counter value. */
z_result_t wz_ext_e2e_sender_protect(const wz_ext_loaned_e2e_sender_t *this_,
                                     size_t stream, const uint8_t *payload,
                                     size_t len, uint8_t *out, size_t capacity,
                                     size_t *written, uint64_t *counter,
                                     z_owned_string_t *refusal);

/* The counter the stream's next frame carries; false when the stream is spent,
 * for no such stream, or a NULL argument. */
bool wz_ext_e2e_sender_next(const wz_ext_loaned_e2e_sender_t *this_,
                            size_t stream, uint64_t *out);

/* Make value the stream's next counter. Z_OK; Z_EINVAL for a value the counter
 * field cannot hold or no such stream; Z_ERR_NULL. */
z_result_t wz_ext_e2e_sender_set(const wz_ext_loaned_e2e_sender_t *this_,
                                 size_t stream, uint64_t value);

const wz_ext_loaned_e2e_sender_t *wz_ext_e2e_sender_loan(
    const wz_ext_owned_e2e_sender_t *this_);
wz_ext_moved_e2e_sender_t *wz_ext_e2e_sender_move(
    wz_ext_owned_e2e_sender_t *this_);
void wz_ext_e2e_sender_drop(wz_ext_moved_e2e_sender_t *this_);
void wz_ext_internal_e2e_sender_null(wz_ext_owned_e2e_sender_t *this_);
bool wz_ext_internal_e2e_sender_check(const wz_ext_owned_e2e_sender_t *this_);

/* How a receiver's streams are chosen. */
#define WZ_EXT_E2E_KEYING_INDEXED 0         /* the program names the stream */
#define WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL 1 /* a slot per sender, in arrival
                                               order (e2e-sender-demux) */
#define WZ_EXT_E2E_KEYING_SENDERS_BOUND 2   /* a slot per listed sender
                                               (e2e-sender-demux) */

/* What a verdict's status says. */
#define WZ_EXT_E2E_OK 0            /* intact, and the next frame */
#define WZ_EXT_E2E_FIRST 1         /* intact, and the stream's baseline */
#define WZ_EXT_E2E_REPEATED 2      /* intact, the same counter again */
#define WZ_EXT_E2E_OUT_OF_RANGE 3  /* intact, a step above the largest gap */
#define WZ_EXT_E2E_COUNTER_ERROR 4 /* either of the two, under a profile that
                                      reports them as one */
#define WZ_EXT_E2E_INTEGRITY 5     /* not intact: failed says which check */
#define WZ_EXT_E2E_UNSLOTTED 6     /* of a sender no slot holds */

/* The bits of failed. */
#define WZ_EXT_E2E_FAILED_CRC 1
#define WZ_EXT_E2E_FAILED_IDENT 2  /* the identifier is not the expected one */
#define WZ_EXT_E2E_FAILED_LENGTH 4 /* the length field disagrees with the
                                      frame */
#define WZ_EXT_E2E_FAILED_SHORT 8  /* shorter than the header */

/* The values of unslotted. */
#define WZ_EXT_E2E_SLOTTED 0
#define WZ_EXT_E2E_NOT_LISTED 1 /* the bound list does not name the sender */
#define WZ_EXT_E2E_SLOTS_FULL 2 /* every slot is another sender's */

/* The bits of has: which numbers of a verdict hold a value (0 otherwise). */
#define WZ_EXT_E2E_HAS_COUNTER 1
#define WZ_EXT_E2E_HAS_STEP 2
#define WZ_EXT_E2E_HAS_KIND 4
#define WZ_EXT_E2E_HAS_RESULT 8
#define WZ_EXT_E2E_HAS_SENDER 16
#define WZ_EXT_E2E_HAS_STREAM 32
#define WZ_EXT_E2E_HAS_SILENCE 64

typedef struct wz_ext_owned_e2e_receiver_t {
  void *_handle;
} wz_ext_owned_e2e_receiver_t;
typedef struct wz_ext_loaned_e2e_receiver_t {
  void *_handle;
} wz_ext_loaned_e2e_receiver_t;
typedef struct wz_ext_moved_e2e_receiver_t {
  wz_ext_owned_e2e_receiver_t _this;
} wz_ext_moved_e2e_receiver_t;

typedef struct wz_ext_e2e_receiver_options_t {
  uint64_t max_gap;       /* the largest gap, at most the profile's ceiling;
                             0 for the profile's own */
  const uint64_t *senders; /* the bound list, BORROWED for the call */
  size_t senders_len;
  size_t streams;         /* streams, or sender slots, at least 1 */
  uint8_t keying;         /* WZ_EXT_E2E_KEYING_* */
} wz_ext_e2e_receiver_options_t;

/* One stream named by the program, the profile's gap. */
void wz_ext_e2e_receiver_options_default(wz_ext_e2e_receiver_options_t *this_);

/* The verdict on one frame. The payload is frame + payload_offset, for
 * payload_len bytes, whatever the status. */
typedef struct wz_ext_e2e_verdict_t {
  uint8_t status;    /* WZ_EXT_E2E_OK ... _UNSLOTTED */
  uint8_t failed;    /* WZ_EXT_E2E_FAILED_* bits */
  uint8_t has;       /* WZ_EXT_E2E_HAS_* bits */
  uint8_t timeout;   /* 1 when the silence before it exceeded the profile's
                        timeout */
  uint8_t unslotted; /* WZ_EXT_E2E_SLOTTED, _NOT_LISTED or _SLOTS_FULL */
  uint8_t reserved[3];
  uint64_t counter;
  uint64_t step;     /* from the stream's baseline */
  uint64_t kind;     /* the message cell's parts */
  uint64_t result;
  uint64_t sender;
  uint64_t silence_ms;
  size_t stream;     /* the stream or slot it was judged in */
  size_t payload_offset;
  size_t payload_len;
} wz_ext_e2e_verdict_t;

/* A receiver of profile_json's frames, made as options says (NULL: the
 * defaults). expected_json gives the identifier the profile's judge.ident
 * names, in the shape of a sender's values text (other fields it states are
 * not read); it may be NULL when the profile judges no identifier. this_ holds
 * the null state on every error; refusal may be NULL.
 *
 * Z_OK; Z_ERR_NULL for a NULL this_ or profile_json; Z_EINVAL (-75) for text
 * that is not UTF-8, an unknown keying, or a NULL senders with a length;
 * WZ_EXT_ERR_UNSUPPORTED for sender keying in a build without
 * e2e-sender-demux; _Z_ERR_CONFIG_INVALID_VALUE (-89) for a profile, expected
 * text or option refused (no stream, a gap above the profile's ceiling, sender
 * keying under a cell with no sender, more slots than E2E_SENDER_SLOTS, a bound
 * list that does not fit), refusal saying why. */
z_result_t wz_ext_e2e_receiver_new(wz_ext_owned_e2e_receiver_t *this_,
                                   const char *profile_json,
                                   const char *expected_json,
                                   const wz_ext_e2e_receiver_options_t *options,
                                   z_owned_string_t *refusal);

/* Judge frame, received at now_ms (the program's clock) on stream; under
 * sender keying stream is 0 and the receiver chooses. Z_OK with the verdict;
 * Z_EINVAL for no such stream (out zeroed, nothing moved); Z_ERR_NULL for a
 * NULL receiver or out, or a NULL frame with a length. */
z_result_t wz_ext_e2e_receiver_judge(const wz_ext_loaned_e2e_receiver_t *this_,
                                     size_t stream, const uint8_t *frame,
                                     size_t len, uint64_t now_ms,
                                     wz_ext_e2e_verdict_t *out);

/* With e2e-sender-demux: how many frames were judged in no slot, by reason
 * (either out may be NULL), and the sender a slot holds (false for a free
 * slot or no such slot). */
z_result_t wz_ext_e2e_receiver_counts(
    const wz_ext_loaned_e2e_receiver_t *this_, uint64_t *not_listed,
    uint64_t *full);
bool wz_ext_e2e_receiver_slot_sender(const wz_ext_loaned_e2e_receiver_t *this_,
                                     size_t slot, uint64_t *out);

const wz_ext_loaned_e2e_receiver_t *wz_ext_e2e_receiver_loan(
    const wz_ext_owned_e2e_receiver_t *this_);
wz_ext_moved_e2e_receiver_t *wz_ext_e2e_receiver_move(
    wz_ext_owned_e2e_receiver_t *this_);
void wz_ext_e2e_receiver_drop(wz_ext_moved_e2e_receiver_t *this_);
void wz_ext_internal_e2e_receiver_null(wz_ext_owned_e2e_receiver_t *this_);
bool wz_ext_internal_e2e_receiver_check(
    const wz_ext_owned_e2e_receiver_t *this_);

/* ---- Instance keys (instance-key) --------------------------------------- */

/* Which instance of a message a sample is, read from fields of its payload.
 * A message is published on one key expression whatever its instance; a
 * KEYER names up to the build's INSTANCE_KEY_FIELDS fields of the payload's
 * protobuf message (integers, enumerations by their numbers, or strings), read
 * through the program's .proto files, and the values each may take. The
 * instance of a sample is the position of its values in the product of those
 * lists, row-major (the last field varies fastest), at most
 * INSTANCES_PER_MESSAGE of them; it is never on the wire. A node makes one
 * keyer per message and direction, with the values it sends or receives.
 *
 * A sample of no instance is DROPPED and counted: its payload is not a message
 * of the schema, a key field that has presence is absent (a field without
 * presence reads as 0 or the empty string), or a value is in no list. Drops are
 * reported at the rate the description states: the first after a quiet
 * interval carries the count since the last report, and with the event-ring
 * capability each report is also an event of WZ_EXT_EVENT_SOURCE_
 * INSTANCE_KEY_DROPPED.
 *
 * The instance is the STREAM of the end-to-end doors: with e2e-receiver,
 * wz_ext_instance_keyer_judge judges a frame in the receiver's stream of the
 * instance its payload is; with e2e-sender, wz_ext_instance_keyer_protect
 * protects a payload on the sender's counter stream of its instance. A receiver
 * that keeps its streams per sender (e2e-sender-demux) is refused: instance
 * keys and sender slots are exclusive on one message. The last value of each
 * instance is kept in storage the program gives.
 *
 * OWNERSHIP AND THREADS. As for the end-to-end doors. The judging and
 * protecting doors hold the keyer's lock, then the receiver's or the
 * sender's. Part of the unstable surface. */

/* One .proto file: the name other files import it by, and its text, both
 * NUL-terminated UTF-8, borrowed for the call. */
typedef struct wz_ext_proto_file_t {
  const char *name;
  const char *text;
} wz_ext_proto_file_t;

typedef struct wz_ext_owned_instance_keyer_t {
  void *_handle;
} wz_ext_owned_instance_keyer_t;
typedef struct wz_ext_loaned_instance_keyer_t {
  void *_handle;
} wz_ext_loaned_instance_keyer_t;
typedef struct wz_ext_moved_instance_keyer_t {
  wz_ext_owned_instance_keyer_t _this;
} wz_ext_moved_instance_keyer_t;

typedef struct wz_ext_instance_keyer_options_t {
  uint8_t *storage;      /* the last values, value_capacity bytes per
                            instance; the program's, valid and untouched until
                            the keyer is dropped */
  size_t storage_len;
  size_t value_capacity; /* 0 keeps no last values */
} wz_ext_instance_keyer_options_t;

/* What became of one sample. */
#define WZ_EXT_INSTANCE_KEY_INDEXED 0     /* instance is its index */
#define WZ_EXT_INSTANCE_KEY_UNDECODABLE 1 /* not a message of the schema, or a
                                             frame shorter than its header */
#define WZ_EXT_INSTANCE_KEY_ABSENT 2      /* field names the absent key field */
#define WZ_EXT_INSTANCE_KEY_NOT_LISTED 3  /* field names the key field whose
                                             value is in no list */

/* What became of the instance's last value. */
#define WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT 0   /* none kept, or dropped */
#define WZ_EXT_INSTANCE_KEY_LAST_RECORDED 1   /* the payload is now its last */
#define WZ_EXT_INSTANCE_KEY_LAST_NOT_INTACT 2 /* the frame is not intact */
#define WZ_EXT_INSTANCE_KEY_LAST_TOO_LONG 3   /* longer than an instance's room */

typedef struct wz_ext_instance_key_t {
  uint8_t status;   /* WZ_EXT_INSTANCE_KEY_* */
  uint8_t reported; /* 1 when this drop carries the report of the drops since
                       the last one */
  uint8_t last;     /* WZ_EXT_INSTANCE_KEY_LAST_* */
  uint8_t reserved;
  uint32_t field;   /* for _ABSENT and _NOT_LISTED, in the description's order */
  uint64_t dropped; /* when reported, the drops since the last report */
  size_t instance;  /* for _INDEXED */
} wz_ext_instance_key_t;

void wz_ext_instance_keyer_options_default(
    wz_ext_instance_keyer_options_t *this_);

/* A keyer of the message description names, over the file_count files
 * (every one is read, with what it imports). description is JSON:
 *   {"message": "<full name, package included>",
 *    "fields": [{"path": "<field>" or "<holder>.<field>",
 *                "values": [<integer>, {"range": [<low>, <high>]}, ...]
 *                          or ["<string>", ...]}, ...],
 *    "report_interval_ms": <n>}
 * options may be NULL (no last values). On _Z_ERR_CONFIG_INVALID_VALUE (-89),
 * for schema files, a description or storage that is refused, refusal (which
 * may be NULL) holds the reason. Z_ERR_NULL (-127) for a NULL argument the
 * call needs; Z_EINVAL (-75) for text that is not UTF-8. */
z_result_t wz_ext_instance_keyer_new(
    wz_ext_owned_instance_keyer_t *this_, const wz_ext_proto_file_t *files,
    size_t file_count, const char *description,
    const wz_ext_instance_keyer_options_t *options,
    z_owned_string_t *refusal);
z_result_t wz_ext_instance_keyer_instances(
    const wz_ext_loaned_instance_keyer_t *this_, size_t *out);
/* The instance payload, received or about to be sent at now_ms, is; an
 * indexed payload becomes the instance's last value. Z_OK whatever out says. */
z_result_t wz_ext_instance_keyer_index(
    const wz_ext_loaned_instance_keyer_t *this_, const uint8_t *payload,
    size_t len, uint64_t now_ms, wz_ext_instance_key_t *out);
/* The report of the drops held since the last one, when the interval has
 * passed: true, out naming the latest drop's reason and the count. */
bool wz_ext_instance_keyer_flush(const wz_ext_loaned_instance_keyer_t *this_,
                                 uint64_t now_ms, wz_ext_instance_key_t *out);
z_result_t wz_ext_instance_keyer_counts(
    const wz_ext_loaned_instance_keyer_t *this_, uint64_t *undecodable,
    uint64_t *absent, uint64_t *not_listed);
/* Copy an instance's last value: Z_OK; Z_CHANNEL_NODATA (2) before its first;
 * Z_ERR_OVERFLOW (-74) when capacity is short (len is the value's length);
 * Z_EINVAL for an instance the keyer has not or a keyer without storage. */
z_result_t wz_ext_instance_keyer_last(
    const wz_ext_loaned_instance_keyer_t *this_, size_t instance, uint8_t *out,
    size_t capacity, size_t *len);
/* Make value an instance's last value (what a publisher sends before its
 * first, say). Z_ERR_OVERFLOW for a value longer than an instance's room. */
z_result_t wz_ext_instance_keyer_set_last(
    const wz_ext_loaned_instance_keyer_t *this_, size_t instance,
    const uint8_t *value, size_t len);
/* With e2e-receiver: judge frame in receiver's stream of the instance its
 * payload (what follows the receiver's header) is. Z_OK whatever key and
 * verdict say; verdict is zeroed for a dropped frame, which moves nothing.
 * _Z_ERR_CONFIG_INVALID_VALUE for a receiver kept per sender or with fewer
 * streams than the keyer has instances. */
z_result_t wz_ext_instance_keyer_judge(
    const wz_ext_loaned_instance_keyer_t *this_,
    const wz_ext_loaned_e2e_receiver_t *receiver, const uint8_t *frame,
    size_t len, uint64_t now_ms, wz_ext_instance_key_t *key,
    wz_ext_e2e_verdict_t *verdict);
/* With e2e-sender: protect payload on sender's counter stream of its
 * instance. Z_EINVAL when the payload is no instance (key says why; nothing is
 * built and no counter value consumed); Z_ERR_OVERFLOW when capacity is
 * short; _Z_ERR_CONFIG_INVALID_VALUE for a sender with fewer streams than the
 * keyer has instances. */
z_result_t wz_ext_instance_keyer_protect(
    const wz_ext_loaned_instance_keyer_t *this_,
    const wz_ext_loaned_e2e_sender_t *sender, const uint8_t *payload,
    size_t len, uint64_t now_ms, uint8_t *out, size_t capacity,
    size_t *written, uint64_t *counter, wz_ext_instance_key_t *key);
const wz_ext_loaned_instance_keyer_t *wz_ext_instance_keyer_loan(
    const wz_ext_owned_instance_keyer_t *this_);
wz_ext_moved_instance_keyer_t *wz_ext_instance_keyer_move(
    wz_ext_owned_instance_keyer_t *this_);
/* The storage of the last values is the program's again once it returns. */
void wz_ext_instance_keyer_drop(wz_ext_moved_instance_keyer_t *this_);
void wz_ext_internal_instance_keyer_null(wz_ext_owned_instance_keyer_t *this_);
bool wz_ext_internal_instance_keyer_check(
    const wz_ext_owned_instance_keyer_t *this_);

/* wz's own result codes of the doors below, outside zenoh-pico's own codes
 * (-128 to -65), so a later zenoh-pico code cannot take them. */
#define WZ_EXT_ERR_POLICY_OFF (-2)  /* the build's policy does not allow what
                                       the call states; nothing was sent */
#define WZ_EXT_ERR_UNSUPPORTED (-3) /* the session's engine, or this build, does
                                       not do what the call asks; nothing was
                                       declared or sent */

/* The declaration watch: what the peers of a session declare and retract,
 * told to the program. Present only in a build with the
 * remote-declaration-watch or the declarations-synced-event capability.
 *
 * A watch is of one kind of entity, and is told each one a peer declares
 * (WZ_EXT_DECL_DECLARED, with the id the peer declared it under and its key)
 * and each one it retracts (WZ_EXT_DECL_UNDECLARED, with the id; the wire
 * names no key). With remote-declaration-watch every event names the peer, as
 * the zenoh id its link's handshake gave; without it zid_len is 0. With
 * declarations-synced-event a watch is told once for each establishment of a
 * link that the peer has sent everything it held when the link came up
 * (WZ_EXT_DECL_SYNCED); without it that event is never told.
 *
 * A watch of subscribers or queryables is told first what each peer holds
 * when it is declared, as WZ_EXT_DECL_DECLARED events ahead of every live
 * event of that link, then what the peers declare and retract from then on,
 * on every link the session holds and every link that comes up later; each
 * declaration is told once. A watch of tokens hears only what comes after it
 * is declared. A watch declared after a link's peer finished its initial
 * declarations is not told WZ_EXT_DECL_SYNCED for that link. A link that is
 * lost tells no undeclaration for what its peer held, and the members of a
 * multicast group are not watched. */

/* What an event says. */
#define WZ_EXT_DECL_DECLARED 0
#define WZ_EXT_DECL_UNDECLARED 1
#define WZ_EXT_DECL_SYNCED 2

/* The kind of entity a watch is of. */
#define WZ_EXT_DECL_SUBSCRIBER 0
#define WZ_EXT_DECL_QUERYABLE 1
#define WZ_EXT_DECL_TOKEN 2

/* One event, as the callback reads it: 48 bytes on a 64-bit target, 40 on a
 * 32-bit one. It and the key it points to are valid only for the call. */
typedef struct wz_ext_decl_event_t {
  uint8_t kind;      /* WZ_EXT_DECL_DECLARED, _UNDECLARED or _SYNCED */
  uint8_t entity;    /* the kind the watch is of: WZ_EXT_DECL_SUBSCRIBER,
                        _QUERYABLE or _TOKEN */
  uint8_t zid_len;   /* how many bytes of zid name the peer; 0 when the peer
                        is not known */
  uint8_t reserved;
  uint32_t reserved2;
  uint64_t id;       /* the id the peer declared the entity under, which its
                        undeclaration names again; 0 for _SYNCED */
  const char *keyexpr; /* the key of a _DECLARED, not NUL-terminated; NULL for
                          the other two */
  size_t keyexpr_len;
  uint8_t zid[16];   /* the peer's zenoh id in the layout of z_id_t, zero past
                        zid_len */
} wz_ext_decl_event_t;

/* The program's callback. It runs where the session hands out its callbacks,
 * with no lock of the library held, so it may call into the session. */
typedef void wz_ext_decl_watch_fn(void *context,
                                  const wz_ext_decl_event_t *event);

/* Runs once, after the last call, when the watch lets go of context. */
typedef void wz_ext_decl_watch_drop_fn(void *context);

/* An owned watch; NULL in _val when it holds none. */
typedef struct wz_ext_owned_decl_watch_t {
  void *_val;
} wz_ext_owned_decl_watch_t;

/* Watch the peers of session for the entity kind named (WZ_EXT_DECL_SUBSCRIBER,
 * _QUERYABLE or _TOKEN), telling each event to call with context, and write
 * the watch to watch. drop may be NULL.
 *
 * The library takes context on every path: on a refusal drop(context) runs
 * before this returns and watch is left NULL. Otherwise drop(context) runs once
 * the watch is dropped, or when the session is closed if that comes first.
 *
 * Z_OK; Z_ERR_NULL for a NULL watch, call or session; Z_ERR_INVALID for
 * another entity kind; Z_ERR_SESSION_CLOSED for a closed session;
 * WZ_EXT_ERR_UNSUPPORTED when the session's engine does not watch (the
 * cooperative engine), or the build hears no declaration of that kind. */
z_result_t wz_ext_decl_watch_declare(const z_loaned_session_t *session,
                                     wz_ext_owned_decl_watch_t *watch,
                                     uint8_t entity,
                                     wz_ext_decl_watch_fn *call,
                                     wz_ext_decl_watch_drop_fn *drop,
                                     void *context);

/* Stop the watch and leave it NULL: no event is told after this returns, and
 * drop(context) has run by then, unless this is called from inside the
 * watch's own callback, when it runs as the callback returns. A NULL watch, or
 * one that holds none, is left as it is. */
void wz_ext_decl_watch_drop(wz_ext_owned_decl_watch_t *watch);

/* z_get, addressed to the one node peer names: it is asked on the link that
 * reaches that node and on no other, not of the session's own queryables and
 * not of a multicast group. A node the session has no link to is not asked,
 * and the get completes with no reply; it is never widened to the others.
 * Present in every build with the query plane; the build's targeted-query
 * policy decides whether it is allowed.
 *
 * callback and the moved parts of options are consumed on every path, as
 * z_get consumes them; on a refusal the callback's drop runs before this
 * returns. WZ_EXT_ERR_POLICY_OFF when the targeted-query policy is off;
 * Z_ERR_INVALID for an all-zero peer; Z_ERR_NULL for a NULL peer;
 * WZ_EXT_ERR_UNSUPPORTED when the session's engine cannot address a get to
 * one node (the cooperative engine); each sends nothing. Otherwise what z_get
 * answers.
 *
 * Declared where the drop-in header declares z_get: its types are the query
 * plane's, which a header without Z_FEATURE_QUERY does not have. */
#if defined(Z_FEATURE_QUERY) && Z_FEATURE_QUERY == 1
z_result_t wz_ext_get_to_peer(const z_loaned_session_t *session,
                              const z_loaned_keyexpr_t *keyexpr,
                              const char *parameters,
                              z_moved_closure_reply_t *callback,
                              z_get_options_t *options, const z_id_t *peer);
#endif

/* ---- The replay cache (replay-cache) ----------------------------------- */

/* What each publisher of a message last sent, for a subscriber that arrives
 * later. Part of the unstable surface, and present only in a build with the
 * replay-cache capability.
 *
 * THE PUBLISHER keeps a ring of depth frames per instance of the message, in
 * the program's storage, each frame exactly as it was sent (a protection
 * header included), recorded before it is put and whether or not the put
 * succeeds. Serving declares a queryable on the message's key followed by the
 * program's suffix, which answers a query with every frame of every ring in
 * ascending (time, instance, sequence) order, from a snapshot taken when the
 * answer begins, then the final; an empty cache answers the final only. Under
 * the session's replay-reply-shape policy segmented, each frame is answered as
 * the pieces of a segment profile, every frame under the next transfer number.
 * Under replay-serve-holds-sends on, a put while an answer is served is held:
 * a periodic one as its instance's latest, an event in a queue of
 * max(1, depth/2) that gives up its oldest; they go out once the last answer
 * is over, oldest first, before any later put.
 *
 * THE SUBSCRIBER subscribes to the key, watches the session's peers for a
 * queryable declared on the suffixed key, and asks each such publisher once,
 * as it appears (addressed to it under the targeted-query policy, otherwise of
 * every node answering the key), at most max_in_flight at once. The replies
 * enter the receive path of the live samples: one receiving judge, which the
 * subscriber takes, judges both, and a reply that repeats the judge's baseline
 * frame, or is behind it by less than depth, is dropped. A round ends when
 * every query ended, or is abandoned when the progress deadline (from the last
 * reply) or the round deadline passes. Under replay-live-before-answer
 * hold-back, the live samples that arrive before the first round is over are
 * held in the program's store and handed on after its replies; under deliver,
 * as they arrive. A publisher whose queryable a link held before the
 * subscriber was made is asked all the same: the declaration watch tells
 * what each peer holds first.
 *
 * TIME is milliseconds: the program's own for a publisher's frames (it orders
 * an answer), and for a subscriber its clock in 32 bits that wrap, given in
 * the options, or the library's monotonic clock when it gives none; the
 * deadlines are judged by wz_ext_replay_subscriber_poll.
 *
 * THREADS. Each door runs under the object's lock. A subscriber's callback
 * runs inside that lock, one sample at a time in the order the judge saw them,
 * on the thread the session hands the sample to or the one that polls, so it
 * must not call a door of its own subscriber. Keep the session (and a
 * publisher's publisher) until the object is dropped. */

#define WZ_EXT_REPLAY_SEND_PERIODIC 0
#define WZ_EXT_REPLAY_SEND_EVENT 1

/* What a put did. */
#define WZ_EXT_REPLAY_SENT 0
#define WZ_EXT_REPLAY_HELD 1
#define WZ_EXT_REPLAY_HELD_REPLACED 2      /* the instance's earlier held frame
                                              will not go out */
#define WZ_EXT_REPLAY_DEFERRED 3
#define WZ_EXT_REPLAY_DEFERRED_OVERWROTE 4 /* the queue gave up its oldest */

/* Where a publisher's cache stands. */
#define WZ_EXT_REPLAY_SERVING_IDLE 0
#define WZ_EXT_REPLAY_SERVING_ANSWERING 1
#define WZ_EXT_REPLAY_SERVING_RELEASING 2
#define WZ_EXT_REPLAY_NO_CACHE 255

/* Where a subscriber's round stands. */
#define WZ_EXT_REPLAY_ROUND_IDLE 0
#define WZ_EXT_REPLAY_ROUND_ASKING 1
#define WZ_EXT_REPLAY_ROUND_ANSWERING 2
#define WZ_EXT_REPLAY_ROUND_ABANDONED 3
#define WZ_EXT_REPLAY_ROUND_LIVE 4
#define WZ_EXT_REPLAY_NO_SUBSCRIBER 255

typedef struct wz_ext_replay_shape_t {
  size_t frame_max;   /* the longest frame kept, at least 1 */
  uint32_t depth;     /* frames per instance, 1 to REPLAY_DEPTH_MAX */
  uint32_t instances; /* at least 1 */
} wz_ext_replay_shape_t;

typedef struct wz_ext_replay_publisher_counts_t {
  uint64_t recorded;
  uint64_t deferred_overwritten;
  uint64_t periodic_replaced;
  uint64_t answers;
} wz_ext_replay_publisher_counts_t;

/* Under segmented: the segment profile and the program's values of its
 * fields (JSON, BORROWED for the call), the first transfer number and the
 * size of a piece's chunk. Not read under frame-per-sample. */
typedef struct wz_ext_replay_serve_options_t {
  const char *segment_profile;
  const char *segment_values;
  uint64_t first_transfer;
  size_t chunk_bytes;
} wz_ext_replay_serve_options_t;

typedef struct wz_ext_owned_replay_publisher_t {
  void *_handle;
} wz_ext_owned_replay_publisher_t;
typedef struct wz_ext_loaned_replay_publisher_t {
  void *_handle;
} wz_ext_loaned_replay_publisher_t;
typedef struct wz_ext_moved_replay_publisher_t {
  wz_ext_owned_replay_publisher_t _this;
} wz_ext_moved_replay_publisher_t;

/* The storage a cache of shape takes; 0 for a NULL shape, one with no depth,
 * instance or frame room, or one whose size overflows. */
size_t wz_ext_replay_publisher_storage_size(const wz_ext_replay_shape_t *shape);

/* A cache of shape over storage, on session (whose policies it reads once),
 * putting the message on publisher. this_ holds the null state on every
 * error; refusal may be NULL. Z_OK; Z_ERR_NULL for a NULL argument;
 * Z_ERR_SESSION_CLOSED; _Z_ERR_CONFIG_INVALID_VALUE (-89) for a shape out of
 * range or storage too short, refusal saying why. */
z_result_t wz_ext_replay_publisher_new(wz_ext_owned_replay_publisher_t *this_,
                                       const z_loaned_session_t *session,
                                       const z_loaned_publisher_t *publisher,
                                       uint8_t *storage, size_t storage_len,
                                       const wz_ext_replay_shape_t *shape,
                                       z_owned_string_t *refusal);

/* Record a frame sent at time_ms on instance, without putting it. Z_OK;
 * Z_EINVAL (-75) for no such instance or a frame past frame_max (nothing
 * recorded); Z_ERR_NULL. */
z_result_t wz_ext_replay_publisher_record(
    const wz_ext_loaned_replay_publisher_t *this_, size_t instance,
    uint64_t time_ms, const uint8_t *frame, size_t len);

/* Record a frame and put it, or hold it while an answer is served under
 * replay-serve-holds-sends; dispatch (may be NULL) says which. Under
 * segmented the frame goes out as the pieces of the serve door's profile, so
 * such a cache puts nothing before it serves. Z_OK when put or held; the
 * put's code when it failed (the frame is recorded); Z_EINVAL for no such
 * instance, a frame past frame_max, an unknown kind, or a segmented cache that
 * does not serve yet (nothing recorded); Z_ERR_NULL. */
z_result_t wz_ext_replay_publisher_put(
    const wz_ext_loaned_replay_publisher_t *this_, size_t instance,
    uint64_t time_ms, const uint8_t *frame, size_t len, uint8_t kind,
    uint8_t *dispatch);

/* No segment profile, chunks of 0 bytes. */
void wz_ext_replay_serve_options_default(wz_ext_replay_serve_options_t *this_);

/* Declare the cache's queryable on keyexpr followed by suffix. options may be
 * NULL under frame-per-sample. Z_OK; Z_ERR_NULL; Z_EINVAL for text that is not
 * UTF-8, a cache that serves already, or a chunk of 0 under segmented;
 * Z_ERR_INVALID for a suffixed key that is no key expression;
 * _Z_ERR_CONFIG_INVALID_VALUE for a segment profile or values refused;
 * otherwise what z_declare_queryable answers. */
z_result_t wz_ext_replay_publisher_serve(
    const wz_ext_loaned_replay_publisher_t *this_,
    const z_loaned_keyexpr_t *keyexpr, const char *suffix,
    const wz_ext_replay_serve_options_t *options, z_owned_string_t *refusal);

/* WZ_EXT_REPLAY_SERVING_*, or WZ_EXT_REPLAY_NO_CACHE. */
uint8_t wz_ext_replay_publisher_phase(
    const wz_ext_loaned_replay_publisher_t *this_);
z_result_t wz_ext_replay_publisher_counts(
    const wz_ext_loaned_replay_publisher_t *this_,
    wz_ext_replay_publisher_counts_t *out);

const wz_ext_loaned_replay_publisher_t *wz_ext_replay_publisher_loan(
    const wz_ext_owned_replay_publisher_t *this_);
wz_ext_moved_replay_publisher_t *wz_ext_replay_publisher_move(
    wz_ext_owned_replay_publisher_t *this_);
/* Undeclares the queryable; the storage is the program's again on return. */
void wz_ext_replay_publisher_drop(wz_ext_moved_replay_publisher_t *this_);
void wz_ext_internal_replay_publisher_null(
    wz_ext_owned_replay_publisher_t *this_);
bool wz_ext_internal_replay_publisher_check(
    const wz_ext_owned_replay_publisher_t *this_);

/* One row of a subscriber's table of publishers. */
typedef struct wz_ext_replay_publisher_slot_t {
  uint64_t _opaque[4];
} wz_ext_replay_publisher_slot_t;

/* The program's clock: writes the milliseconds of a monotonic source and
 * returns 0, or returns anything else when it cannot say what time it is. */
typedef int8_t wz_ext_replay_clock_fn(void *context, uint32_t *now_ms);

/* One sample handed to the program: 120 bytes on a 64-bit target. It and the
 * frame it points to are valid only for the call. */
typedef struct wz_ext_replay_sample_t {
  const uint8_t *frame;
  size_t len;
  wz_ext_e2e_verdict_t verdict; /* zero when judged is 0 */
  uint8_t from_replay;          /* 1 for a reply, 0 for a live sample */
  uint8_t judged;               /* 0 when stream is none the receiver has */
  uint8_t zid_len;              /* the replying publisher; 0 when live */
  uint8_t reserved;
  uint8_t zid[16];
} wz_ext_replay_sample_t;

typedef void wz_ext_replay_deliver_fn(void *context,
                                      const wz_ext_replay_sample_t *sample);
typedef void wz_ext_replay_drop_fn(void *context);

typedef struct wz_ext_replay_subscriber_options_t {
  wz_ext_replay_publisher_slot_t *slots; /* at least one row */
  size_t slot_count;
  uint8_t *held;    /* under hold-back: cells of 4 + held_cell bytes */
  size_t held_len;
  size_t held_cell; /* the longest live sample held */
  size_t depth;     /* the publishers' ring depth, at least 1 */
  size_t max_in_flight; /* 0: no bound of its own; never above
                           QUERIER_MAX_PENDING_QUERIES (0: none) */
  size_t stream;    /* the receiver's stream (0 under sender keying) */
  uint32_t progress_ms; /* 1 to 2147483647, no default */
  uint32_t round_ms;    /* 1 to 2147483647, no default */
  wz_ext_replay_clock_fn *clock; /* NULL: the library's clock */
  void *clock_context;
  const char *segment_profile; /* under segmented: the pieces' profile (JSON,
                                  BORROWED); not read otherwise */
} wz_ext_replay_subscriber_options_t;

typedef struct wz_ext_replay_subscriber_counts_t {
  uint64_t late_replies;
  uint64_t unknown_replies;
  uint64_t duplicates;
  uint64_t stale;
  uint64_t held;
  uint64_t table_full;
  uint64_t abandoned;
  uint64_t frames_given_up; /* segmented: a piece never came */
  uint64_t unjoined_pieces; /* segmented: not a piece, bad CRC, no place */
} wz_ext_replay_subscriber_counts_t;

typedef struct wz_ext_owned_replay_subscriber_t {
  void *_handle;
} wz_ext_owned_replay_subscriber_t;
typedef struct wz_ext_loaned_replay_subscriber_t {
  void *_handle;
} wz_ext_loaned_replay_subscriber_t;
typedef struct wz_ext_moved_replay_subscriber_t {
  wz_ext_owned_replay_subscriber_t _this;
} wz_ext_moved_replay_subscriber_t;

/* No storage, a depth of 1, the querier's bound, stream 0, the library's
 * clock, and no deadlines. */
void wz_ext_replay_subscriber_options_default(
    wz_ext_replay_subscriber_options_t *this_);

/* A replay subscriber of keyexpr on session, watching for keyexpr followed by
 * suffix, judging by receiver (taken), handing each sample to deliver. The
 * receiver and context are taken on every path: on a refusal the receiver is
 * dropped and drop(context) runs before this returns. Z_OK; Z_ERR_NULL;
 * Z_ERR_SESSION_CLOSED; Z_EINVAL (-75) for an option out of range;
 * Z_ERR_INVALID for a suffixed key that is no key expression; under
 * replay-reply-shape segmented, Z_ERR_NULL for no segment_profile and
 * _Z_ERR_CONFIG_INVALID_VALUE for one refused; otherwise what declaring the
 * subscription or the watch answers. Under segmented every payload, live or
 * replied, is joined from its pieces before it is judged; a frame with a
 * piece missing is given up and counted. */
z_result_t wz_ext_replay_subscriber_new(
    wz_ext_owned_replay_subscriber_t *this_, const z_loaned_session_t *session,
    const z_loaned_keyexpr_t *keyexpr, const char *suffix,
    wz_ext_moved_e2e_receiver_t *receiver,
    const wz_ext_replay_subscriber_options_t *options,
    wz_ext_replay_deliver_fn *deliver, wz_ext_replay_drop_fn *drop,
    void *context);

/* Judge the deadlines now and hand on what an ended round released. */
z_result_t wz_ext_replay_subscriber_poll(
    const wz_ext_loaned_replay_subscriber_t *this_);
/* WZ_EXT_REPLAY_ROUND_*, or WZ_EXT_REPLAY_NO_SUBSCRIBER. */
uint8_t wz_ext_replay_subscriber_phase(
    const wz_ext_loaned_replay_subscriber_t *this_);
z_result_t wz_ext_replay_subscriber_counts(
    const wz_ext_loaned_replay_subscriber_t *this_,
    wz_ext_replay_subscriber_counts_t *out);

const wz_ext_loaned_replay_subscriber_t *wz_ext_replay_subscriber_loan(
    const wz_ext_owned_replay_subscriber_t *this_);
wz_ext_moved_replay_subscriber_t *wz_ext_replay_subscriber_move(
    wz_ext_owned_replay_subscriber_t *this_);
/* Nothing is handed on after this returns; drop(context) has run. */
void wz_ext_replay_subscriber_drop(wz_ext_moved_replay_subscriber_t *this_);
void wz_ext_internal_replay_subscriber_null(
    wz_ext_owned_replay_subscriber_t *this_);
bool wz_ext_internal_replay_subscriber_check(
    const wz_ext_owned_replay_subscriber_t *this_);

/* ---- Declarations told again ------------------------------------------- */

/* Tell the peer of every link of the session that is up everything the
 * session holds again (its subscriptions, queryables, tokens and interests),
 * as a link that has just come up is told, at the pace the session states.
 * Nothing the session holds changes: each entity keeps its id and its route.
 * For a program that holds that a peer lost declarations the session made.
 * Part of the unstable surface.
 *
 * The number of links told (0 when none is up), Z_ERR_SESSION_CLOSED for a
 * closed session, WZ_EXT_ERR_UNSUPPORTED when the session's engine keeps no
 * record of what it declared, Z_ERR_NULL for a null session. */
z_result_t wz_ext_redeclare(const z_loaned_session_t *session);

/* The conformance digest of this build, read from the configuration it
 * was built with: "sha256:" and 64 lowercase hex digits, NUL-terminated and
 * static. It is the digest wz_config.py prints in the conformance statement
 * of the configuration the library was built with (every capability of the
 * ABI and whether the build has it, every limit and policy value), so a
 * tester holding a statement can tell whether this library is that build.
 * Present in every build. */
const char *wz_ext_conformance_digest(void);

/* ---- Key ids every node of a deployment shares (shared-key-ids) ---- */

/* Hand config the key ids every node of the deployment shares: count
 * entries, entry i the id ids[i] and the key expression keys[i], a
 * NUL-terminated UTF-8 string. The session z_open makes of the config holds
 * the dictionary: it reads an id the dictionary names though its peer never
 * declared it, declares no key expression under one of its ids, and names a
 * key by one as its key-wire-form policy says (shared: the key's id, or the
 * id of the longest entry that ends at one of its slashes followed by the
 * rest, whichever is cheaper than the whole key). A count of 0 takes back a
 * dictionary handed before. Every node of the deployment must hand the same
 * dictionary; a peer without it cannot read a key named by one of its ids.
 * The config's document may state the same as wz/key-ids
 * (wz_ext_config_document): a dictionary handed here replaces the
 * document's, a form stated for an endpoint here replaces the document's
 * for that endpoint, and what is not stated here is the document's.
 * Part of the unstable surface, and present only in a build with the
 * shared-key-ids capability.
 *
 * Z_OK; Z_ERR_NULL for a NULL config, a NULL array with entries, or a NULL
 * key; Z_ERR_INVALID for a key that is not UTF-8 or not a canonical key
 * expression, an id of 0, and an id or a key named twice; Z_ERR_OVERFLOW for
 * more entries than the build's MAX_SHARED_KEY_IDS. A refused call leaves
 * the config as it was.
 *
 * z_open then refuses with Z_ERR_INVALID a session whose key-wire form, or
 * the form stated for one of its endpoints, is shared and whose config
 * states no dictionary. */
z_result_t wz_ext_config_key_ids(z_loaned_config_t *config,
                                 const uint16_t *ids,
                                 const char *const *keys, size_t count);

/* State the key-wire form of the link to locator apart from the session's:
 * form is "declared", "shared" or "literal", as the key-wire-form policy
 * names its values, and locator an endpoint the config dials or listens on,
 * written as the config writes it. A link whose endpoint no statement names
 * takes the session's form; a second statement for one endpoint replaces the
 * first. A link is named by its endpoint because the peer's zid is not known
 * before the handshake. Part of the unstable surface, and present only in a
 * build with the shared-key-ids capability.
 *
 * Z_OK; Z_ERR_NULL for a NULL config, locator or form; Z_ERR_INVALID for text
 * that is not UTF-8, an empty locator, or a form the policy has no value of;
 * WZ_EXT_ERR_POLICY_OFF for a form the build's domain of key-wire-form leaves
 * out. A refused call leaves the config as it was. */
z_result_t wz_ext_config_key_wire_form_for(z_loaned_config_t *config,
                                           const char *locator,
                                           const char *form);

/* ================================================ the periodic run API
 *
 * No door of wz's own: this section states the order in which a program that
 * runs its own scheduler calls zenoh-pico's run API on the pico C ABI, and
 * what each call does on each engine (docs/periodic-run-api.md has the table;
 * crates/wz-capi-pico/examples/c/periodic.c runs it).
 *
 *   1 open       z_open. Multi-threaded arm: the read task starts with the
 *                session unless the open options say not to.
 *   2 tasks      Multi-threaded: zp_start_read_task if the open did not; a
 *                program may open without it, declare, then start it.
 *                zp_start_lease_task / zp_stop_lease_task answer Z_OK and do
 *                nothing, as in zenoh-pico 1.10. Single-threaded: no task.
 *   3 declare    A subscriber the program reads on its own thread hands its
 *                samples to a ring or fifo channel; the program pulls with
 *                the channel's try_recv until Z_CHANNEL_NODATA.
 *   4 each cycle zp_batch_start, the cycle's puts, zp_batch_flush: the puts
 *                leave together at the flush, and the window stays open.
 *                Single-threaded: then zp_spin_once. Then pull the channels.
 *                Then wait for the cycle's absolute deadline (z_clock_now,
 *                z_clock_advance_ms) with z_condvar_wait_until or a sleep.
 *   5 end        zp_batch_stop, the undeclarations, zp_stop_read_task if
 *                wanted, z_close.
 *
 * THE TWO ENGINES. The cooperative engine does the single-threaded arm's work
 * in the calls: zp_read and zp_spin_once read and run the callbacks on the
 * caller's thread, zp_send_keep_alive sends one. The tokio engine reads,
 * keeps the lease and runs the callbacks on a thread of its own in either arm:
 * its zp_read, zp_send_keep_alive and zp_spin_once answer for a live session
 * and do no work, and its zp_send_join asks a joined group for a Join. A
 * program built for the single-threaded arm's promise that callbacks run only
 * inside its own calls therefore locks what its callbacks share, or reads
 * through channels, when its library runs the tokio engine (on Windows, the
 * only engine). In the multi-threaded arm neither engine, nor zenoh-pico, has
 * a call that steps the session on the program's thread: the program sends
 * and pulls, the read task does the rest. */

/* ================================================ the program's transport
 *
 * A transport the program supplies: a program with a network stack of its
 * own (its TCP/IP and UDP) gives the session that stack in place of the
 * system's sockets. The session calls the program's open, send and close; the
 * program calls wz_ext_transport_received, _event and _accepted when its stack
 * has something to say. Part of the unstable surface, and present only in a
 * build with the app-transport capability.
 *
 * WHAT IT CARRIES. A config given a transport (wz_ext_config_transport) opens
 * every link of its session over it and none over the system's sockets:
 *   tcp/ connect   a stream the session dials        WZ_EXT_LINK_STREAM_DIAL
 *   tcp/ listen    a stream listener                 WZ_EXT_LINK_STREAM_LISTEN
 *   udp/ connect   a unicast datagram link           WZ_EXT_LINK_DATAGRAM
 *   udp/ listen    with #iface=, a multicast group   WZ_EXT_LINK_GROUP
 *   udp/ listen    without, a datagram listener      WZ_EXT_LINK_DATAGRAM_LISTEN
 * On a listener of either kind the program names each stream, or each
 * source that sends datagrams to it, with wz_ext_transport_accepted, and
 * hands in what arrives on the link that returns.
 * Either engine of the library runs a session over it. z_open refuses a config
 * whose transport cannot carry what it names: another scheme (tls/, serial/,
 * ...), or a kind this build has no link of (a udp/ dial or a datagram
 * listener on the tokio engine without the udp link, a group without the
 * multicast transport, which the cooperative engine has not), with
 * _Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN
 * (-92), as the same locator over the system's sockets is; a config with
 * neither connect nor listen (it would scout on the system's sockets) with
 * WZ_EXT_ERR_UNSUPPORTED (-3). A stream is framed by the session exactly as a
 * TCP socket is (the two-byte length before each batch), so the program
 * carries plain bytes. A datagram is one batch, taken whole or not at all: a
 * send answered with fewer bytes than it was given fails it. A group's
 * datagrams are handed in with the locator each came from
 * ("udp/<address>:<port>"), which tells the members apart; leaving the group
 * is the link's close.
 *
 * THE RECEIVE BOUND. A link queues at most APP_LINK_QUEUE_BYTES (a limit of
 * the build) of bytes the session has not read. wz_ext_transport_received past
 * it answers WZ_EXT_ERR_LINK_FULL and takes nothing; once the session has read
 * the queue down to half, the transport calls the program's drained(context,
 * link), from a session thread, and the program hands the same bytes in
 * again. A program that gives no drained retries on its own. An empty queue
 * takes any datagram, however large.
 *
 * WHO OWNS WHAT. The program makes the transport (wz_ext_transport_new) and
 * names it in every call it makes, so it can hand in bytes while z_open is
 * still running the handshake of a dial. A config given the transport holds
 * a reference, and so does a session opened from it, for as long as it has a
 * link; the program's own reference goes with wz_ext_transport_drop. The
 * program's drop(context), when it is not NULL, runs once, after the last
 * call of open, send and close, when the last reference goes.
 *
 * HANDLES. The session names every link. open is handed the handle of the
 * link it opens, and the handle is valid before open is called, so the
 * program may report it connected, or hand in its first bytes, from its own
 * thread before open returns. A stream the program accepts on a listener is
 * named by wz_ext_transport_accepted, which returns its handle. A handle is
 * never 0 and never reused while the transport lives.
 *
 * BUFFERS. The bytes of send are valid only during the call: the program
 * copies what it keeps. The bytes of wz_ext_transport_received are copied
 * before it returns: the buffer is the program's again at once. Every string
 * either side passes is NUL-terminated and valid only during the call.
 *
 * WHAT THE PROGRAM'S ANSWERS DO.
 *   open  OK           the link is up now
 *         WOULD_BLOCK  under way: report CONNECTED, or CLOSED if it fails
 *         CLOSED, FAILED, anything else
 *                      the open failed; the session reports it as a link that
 *                      did not open (a dial is retried on its schedule)
 *   send  OK, *written = n (0 < n <= len)
 *                      n bytes taken; the session sends the rest from n
 *         OK with *written = 0, or WOULD_BLOCK
 *                      nothing taken; the session sends nothing more on the
 *                      link until the program reports WRITABLE, then resumes
 *                      with the same bytes
 *         CLOSED       the link is closed; the session closes it as it closes
 *                      a socket the peer closed, and a dialled session dials
 *                      again on its reconnect schedule
 *         FAILED, anything else, or *written > len
 *                      the link has failed and is closed, as CLOSED
 * The program's events:
 *   CONNECTED          the link the session asked to open is up
 *   CLOSED             the link is gone (or its open failed); bytes already
 *                      handed in are still read, and every later call on it
 *                      is refused
 *   WRITABLE           a link whose send would block takes bytes again
 * A WRITABLE that arrives between a send's WOULD_BLOCK and the session hearing
 * it is not lost: that send is made again at once.
 *
 * THREADS. The session calls open, send, close and drained from its own
 * threads (on the cooperative engine, the thread that steps the session), one
 * call at a time per link, and never while it holds a lock of its own: a call
 * may call back into the transport (report CLOSED from inside close, hand
 * bytes to another link from inside send). The program's calls may come from
 * any thread, including from inside open, send and close: each takes the
 * transport's table for the length of one copy, never waits on the session,
 * and wakes the session's tasks after letting go of it. open, send and close
 * must not block for long: a send that cannot take the bytes now answers
 * WOULD_BLOCK.
 */

typedef uint64_t wz_ext_link_t;

typedef uint8_t wz_ext_link_kind_t;
#define WZ_EXT_LINK_STREAM_DIAL 0
#define WZ_EXT_LINK_STREAM_LISTEN 1
#define WZ_EXT_LINK_DATAGRAM 2
#define WZ_EXT_LINK_GROUP 3
#define WZ_EXT_LINK_DATAGRAM_LISTEN 4

typedef int8_t wz_ext_link_result_t;
#define WZ_EXT_LINK_OK 0
#define WZ_EXT_LINK_WOULD_BLOCK 1
#define WZ_EXT_LINK_CLOSED 2
#define WZ_EXT_LINK_FAILED 3

typedef uint8_t wz_ext_link_event_t;
#define WZ_EXT_LINK_EVENT_CONNECTED 0
#define WZ_EXT_LINK_EVENT_CLOSED 1
#define WZ_EXT_LINK_EVENT_WRITABLE 2

/* What the program's calls into the transport return beyond Z_OK, Z_ERR_NULL
 * and Z_EINVAL (-75). wz's own, as WZ_EXT_ERR_POLICY_OFF is. */
#define WZ_EXT_ERR_LINK_UNKNOWN (-4)  /* the transport holds no such link: it
                                         never did, or the session let it go */
#define WZ_EXT_ERR_LINK_NOT_OPEN (-5) /* not up yet: bytes or an accept before
                                         CONNECTED */
#define WZ_EXT_ERR_LINK_CLOSED (-6)   /* closing or closed: nothing taken */
#define WZ_EXT_ERR_LINK_KIND (-7)     /* not for this kind of link: bytes on a
                                         listener, an accept on a stream */
#define WZ_EXT_ERR_LINK_FULL (-8)     /* the link queues its bound: nothing
                                         taken, hand it in again after
                                         drained */

/* The calls the program supplies. open, send and close are required; drained
 * and drop may be NULL. */
typedef struct wz_ext_transport_t {
  void *context;
  wz_ext_link_result_t (*open)(void *context, wz_ext_link_t link,
                               wz_ext_link_kind_t kind, const char *locator);
  wz_ext_link_result_t (*send)(void *context, wz_ext_link_t link,
                               const uint8_t *data, size_t len,
                               size_t *written);
  void (*close)(void *context, wz_ext_link_t link);
  void (*drained)(void *context, wz_ext_link_t link);
  void (*drop)(void *context);
} wz_ext_transport_t;

typedef struct wz_ext_owned_transport_t {
  void *_handle;
} wz_ext_owned_transport_t;
typedef struct wz_ext_loaned_transport_t {
  void *_handle;
} wz_ext_loaned_transport_t;
typedef struct wz_ext_moved_transport_t {
  wz_ext_owned_transport_t _this;
} wz_ext_moved_transport_t;

/* A transport over the calls in transport, which is copied. this_ holds the
 * null state on every error. Z_OK; Z_ERR_NULL for a NULL this_ or transport,
 * or a NULL open, send or close. */
z_result_t wz_ext_transport_new(wz_ext_owned_transport_t *this_,
                                const wz_ext_transport_t *transport);

/* The session opened from config uses transport for every link its connect
 * and listen locators name; a second call replaces the first. The config
 * holds a reference of its own. Z_OK; Z_ERR_NULL for a NULL config, a NULL
 * transport or the null state. */
z_result_t wz_ext_config_transport(z_loaned_config_t *config,
                                   const wz_ext_loaned_transport_t *transport);

/* Bytes that arrived on link, copied before this returns; source is the
 * locator a datagram came from, or NULL (a group's datagrams need one). Z_OK;
 * Z_ERR_NULL for a NULL transport, NULL data with a length, or a group's
 * datagram with no source; Z_EINVAL for a source that is not UTF-8;
 * WZ_EXT_ERR_LINK_UNKNOWN, _NOT_OPEN, _CLOSED or _KIND; WZ_EXT_ERR_LINK_FULL
 * past the receive bound, nothing taken. */
z_result_t wz_ext_transport_received(const wz_ext_loaned_transport_t *transport,
                                     wz_ext_link_t link, const uint8_t *data,
                                     size_t len, const char *source);

/* What happened to link: WZ_EXT_LINK_EVENT_CONNECTED, _CLOSED or _WRITABLE.
 * Z_OK; Z_ERR_NULL for a NULL transport; Z_EINVAL for another event;
 * WZ_EXT_ERR_LINK_UNKNOWN, or WZ_EXT_ERR_LINK_CLOSED for a link already
 * closed. */
z_result_t wz_ext_transport_event(const wz_ext_loaned_transport_t *transport,
                                  wz_ext_link_t link,
                                  wz_ext_link_event_t event);

/* A stream the program accepted on listener, whose remote end it names remote
 * (a locator such as "tcp/<address>:<port>"); out_link receives the new
 * link's handle, and 0 on every error. Z_OK; Z_ERR_NULL for a NULL transport,
 * remote or out_link; Z_EINVAL for a remote that is not UTF-8;
 * WZ_EXT_ERR_LINK_UNKNOWN, _NOT_OPEN (not listening yet), _CLOSED or _KIND
 * (not a listener). */
z_result_t wz_ext_transport_accepted(const wz_ext_loaned_transport_t *transport,
                                     wz_ext_link_t listener, const char *remote,
                                     wz_ext_link_t *out_link);

const wz_ext_loaned_transport_t *wz_ext_transport_loan(
    const wz_ext_owned_transport_t *this_);
wz_ext_moved_transport_t *wz_ext_transport_move(
    wz_ext_owned_transport_t *this_);
void wz_ext_transport_drop(wz_ext_moved_transport_t *this_);
void wz_ext_internal_transport_null(wz_ext_owned_transport_t *this_);
bool wz_ext_internal_transport_check(const wz_ext_owned_transport_t *this_);

/* ================================================ the message catalog
 *
 * A deployment's messages, declared once as data: one JSON5 text names the
 * nodes, the e2e and segment profiles, and for each message its key
 * expression, its id, the nodes that publish and subscribe to it, its period
 * (none for an event message), its protection (a profile and the header
 * values), the senders a receiver binds its slots to, its instance key, its
 * replay depth, its supervision and its segment profile. The library reads
 * and judges it once; the program then asks, per message, for its entry and
 * for the pieces the other doors take, so one library serves every deployment
 * whose catalog it is given. The shape is deploy/message-catalog.schema.json.
 * Part of the unstable surface, and present only in a build with the
 * message-catalog capability; the doors that make a sender, a receiver or
 * supervision rows also need e2e-sender, e2e-receiver or e2e-supervision.
 *
 * A message and a node are named by their index: the place of the message in
 * the catalog's messages and of the node in its nodes. A catalog does not
 * change once read, so several threads may read one at once; a key expression
 * an entry points at lives as long as the catalog. */

#define WZ_EXT_MESSAGE_PUBLISHES 1  /* the node publishes the message */
#define WZ_EXT_MESSAGE_SUBSCRIBES 2 /* the node subscribes to it */

/* The bits of has: what an entry states. */
#define WZ_EXT_MESSAGE_HAS_PERIOD 1
#define WZ_EXT_MESSAGE_HAS_PROTECTION 2
#define WZ_EXT_MESSAGE_HAS_SENDERS 4
#define WZ_EXT_MESSAGE_HAS_INSTANCE_KEY 8
#define WZ_EXT_MESSAGE_HAS_REPLAY 16
#define WZ_EXT_MESSAGE_HAS_SUPERVISION 32
#define WZ_EXT_MESSAGE_HAS_SEGMENT_PROFILE 64

typedef struct wz_ext_owned_message_catalog_t {
  void *_handle;
} wz_ext_owned_message_catalog_t;
typedef struct wz_ext_loaned_message_catalog_t {
  void *_handle;
} wz_ext_loaned_message_catalog_t;
typedef struct wz_ext_moved_message_catalog_t {
  wz_ext_owned_message_catalog_t _this;
} wz_ext_moved_message_catalog_t;

/* One message's entry. A number whose has bit is clear is 0. */
typedef struct wz_ext_message_entry_t {
  const char *key_expr;   /* the literal key it is put on, valid while the
                             catalog lives */
  uint32_t id;
  uint32_t period_ms;     /* 0 for an event message */
  uint32_t replay_depth;  /* 0 for no replay */
  uint16_t supervision_factor; /* 0 when its reception is not supervised */
  uint8_t has;            /* WZ_EXT_MESSAGE_HAS_* */
  uint8_t supervision_awaited; /* 1 when a stream can be lost before its
                                  first reception */
  uint32_t senders;       /* how many senders its receivers bind slots to */
  uint32_t reserved;
} wz_ext_message_entry_t;

/* Read and judge the catalog text, against the build's
 * MESSAGE_CATALOG_ENTRIES, REPLAY_DEPTH_MAX, E2E_SENDER_SLOTS,
 * INSTANCE_KEY_FIELDS and INSTANCES_PER_MESSAGE. this_ holds
 * the null state on every error; refusal may be NULL and, on
 * _Z_ERR_CONFIG_INVALID_VALUE (-89), holds why: the refusal's word (the
 * schema's x-wz-refusals, such as duplicate_id or replay_depth_out_of_range),
 * the JSON pointer to the place, and a sentence.
 *
 * Z_OK; Z_ERR_NULL for a NULL this_ or text; Z_EINVAL (-75) for text that is
 * not UTF-8; _Z_ERR_CONFIG_INVALID_VALUE for a catalog refused. */
z_result_t wz_ext_message_catalog_new(wz_ext_owned_message_catalog_t *this_,
                                      const char *text,
                                      z_owned_string_t *refusal);

/* How many messages it declares; 0 for a NULL catalog. */
size_t wz_ext_message_catalog_len(const wz_ext_loaned_message_catalog_t *this_);

/* The index of the message put on key_expr, of the message of id, and of the
 * node called name. Z_OK; Z_ERR_INVALID (-1) when there is none; Z_EINVAL for
 * text that is not UTF-8; Z_ERR_NULL for a NULL argument. */
z_result_t wz_ext_message_catalog_find(
    const wz_ext_loaned_message_catalog_t *this_, const char *key_expr,
    size_t *out_index);
z_result_t wz_ext_message_catalog_find_id(
    const wz_ext_loaned_message_catalog_t *this_, uint32_t id,
    size_t *out_index);
z_result_t wz_ext_message_catalog_node(
    const wz_ext_loaned_message_catalog_t *this_, const char *name,
    size_t *out_node);

/* The entry of message index, written to out (zeroed on every error). Z_OK;
 * Z_ERR_INVALID for no such message; Z_ERR_NULL for a NULL argument. */
z_result_t wz_ext_message_catalog_entry(
    const wz_ext_loaned_message_catalog_t *this_, size_t index,
    wz_ext_message_entry_t *out);

/* Whether node publishes or subscribes to message index: the
 * WZ_EXT_MESSAGE_PUBLISHES and _SUBSCRIBES bits, 0 for neither or no such
 * message or node. */
uint8_t wz_ext_message_catalog_direction(
    const wz_ext_loaned_message_catalog_t *this_, size_t index, size_t node);

/* The start delay every reception supervisor of the deployment is made with,
 * in milliseconds; 0 when the catalog states none. */
uint32_t wz_ext_message_catalog_supervision_start_delay(
    const wz_ext_loaned_message_catalog_t *this_);

/* With e2e-sender: the sender node protects message index with, from the
 * message's profile and header values and the node's address, made as
 * options says (NULL: the defaults); the handle wz_ext_e2e_sender_new makes.
 * out holds the null state on every error; refusal may be NULL.
 *
 * Z_OK; Z_ERR_INVALID for no such message or node; Z_EINVAL for an unknown
 * rollover; _Z_ERR_CONFIG_INVALID_VALUE when the node does not publish the
 * message, the message is not protected or an option is refused, refusal
 * saying why; Z_ERR_NULL for a NULL catalog or out. */
z_result_t wz_ext_message_catalog_e2e_sender_new(
    const wz_ext_loaned_message_catalog_t *this_, size_t index, size_t node,
    const wz_ext_e2e_sender_options_t *options, wz_ext_owned_e2e_sender_t *out,
    z_owned_string_t *refusal);

/* With e2e-receiver: the receiver node judges message index with, from the
 * message's profile and header values, with one slot per sender the entry
 * lists, bound to its identity, or one stream when it lists none; the handle
 * wz_ext_e2e_receiver_new makes. out holds the null state on every error.
 *
 * Z_OK; Z_ERR_INVALID for no such message or node; WZ_EXT_ERR_UNSUPPORTED for
 * a message that lists senders in a build without e2e-sender-demux;
 * _Z_ERR_CONFIG_INVALID_VALUE when the node does not subscribe to the message
 * or it is not protected, refusal saying why; Z_ERR_NULL for a NULL catalog
 * or out. */
z_result_t wz_ext_message_catalog_e2e_receiver_new(
    const wz_ext_loaned_message_catalog_t *this_, size_t index, size_t node,
    wz_ext_owned_e2e_receiver_t *out, z_owned_string_t *refusal);

/* With e2e-supervision: how many rows a reception supervisor of node takes
 * for message index (one per sender the entry lists, else one), and the door
 * that adds them to supervisor: the message's period and factor, each row's
 * sender the index of the node that sends the stream (the number
 * wz_ext_stream_supervisor_set_sender_present takes). The stream numbers are
 * written to out_streams in the order of the receiver's slots, and how many
 * to written.
 *
 * Z_OK; Z_ERR_OVERFLOW (-74) when capacity is less than the rows, before any
 * is added; Z_ERR_INVALID for no such message or node;
 * _Z_ERR_CONFIG_INVALID_VALUE when the node does not subscribe to the message
 * or its reception is not supervised; the code of
 * wz_ext_stream_supervisor_add when the supervisor refuses a row, the rows
 * before it added and counted in written; Z_ERR_NULL for a NULL argument. */
z_result_t wz_ext_message_catalog_supervision_rows(
    const wz_ext_loaned_message_catalog_t *this_, size_t index, size_t node,
    size_t *out_rows, z_owned_string_t *refusal);
z_result_t wz_ext_message_catalog_supervise(
    const wz_ext_loaned_message_catalog_t *this_, size_t index, size_t node,
    const wz_ext_loaned_stream_supervisor_t *supervisor, uint32_t *out_streams,
    size_t capacity, size_t *written, z_owned_string_t *refusal);

const wz_ext_loaned_message_catalog_t *wz_ext_message_catalog_loan(
    const wz_ext_owned_message_catalog_t *this_);
wz_ext_moved_message_catalog_t *wz_ext_message_catalog_move(
    wz_ext_owned_message_catalog_t *this_);
void wz_ext_message_catalog_drop(wz_ext_moved_message_catalog_t *this_);
void wz_ext_internal_message_catalog_null(
    wz_ext_owned_message_catalog_t *this_);
bool wz_ext_internal_message_catalog_check(
    const wz_ext_owned_message_catalog_t *this_);

#endif /* WZ_EXT_H */
