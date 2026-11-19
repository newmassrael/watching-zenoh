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
 * call replaces the first. */
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
 * A watch hears the peers from the moment it is declared, on every link the
 * session holds and every link that comes up later; what a peer declared
 * before is not told again. A link that is lost tells no undeclaration for
 * what its peer held, and the members of a multicast group are not watched. */

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

/* The conformance digest of this build, read from the configuration it
 * was built with: "sha256:" and 64 lowercase hex digits, NUL-terminated and
 * static. It is the digest wz_config.py prints in the conformance statement
 * of the configuration the library was built with (every capability of the
 * ABI and whether the build has it, every limit and policy value), so a
 * tester holding a statement can tell whether this library is that build.
 * Present in every build. */
const char *wz_ext_conformance_digest(void);

#endif /* WZ_EXT_H */
