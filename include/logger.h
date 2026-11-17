/*
 * logger.h
 * ---------------------------------------------------------------------------
 * Thread-safe event logger: writes coloured lines to the console and plain
 * UTF-8 text to a log file.
 *
 * Log line layout:
 *   2026-11-16 10:00:00 [cycle #3] [RWX] Warning: ...
 *
 * The cycle tag makes it easy to correlate events with a specific
 * 3-second recording window, which is the whole point of the
 * "scan every 20 s / record 3 s" cadence.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_LOGGER_H
#define TRACKER_CORE_LOGGER_H

#include "tracker_types.h"

#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Logger {
    FILE           *file;            /* log file, may be NULL (console only) */
    int             use_color;       /* emit ANSI colour codes on console     */
    int             echo_console;    /* also print to stdout                  */
    uint64_t        cycle;           /* current scheduler cycle number        */
    uint64_t        window_start_ns; /* start of the current recording window */
    uint64_t        lines_written;   /* total lines written (console+file)    */
    pthread_mutex_t lock;            /* serialises concurrent writers         */
    char            path[512];       /* log file path                         */
} Logger;

/* Open the log file.  `path` may be NULL to disable file logging.
 * `use_color` 1 enables ANSI colours on the console.
 * Returns 0 on success, -1 if the file could not be opened. */
int  logger_open(Logger *lg, const char *path, int use_color);

/* Flush and close the log file.  Safe to call twice. */
void logger_close(Logger *lg);

/* Set the cycle number shown in every subsequent line. */
void logger_set_cycle(Logger *lg, uint64_t cycle, uint64_t window_start_ns);

/* Force any buffered data to disk. */
void logger_flush(Logger *lg);

/* printf-style event logging.  Severity is derived from the event type. */
void log_event(Logger *lg, EventType type, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* printf-style event logging with an explicit severity override. */
void log_event_sev(Logger *lg, EventType type, Severity sev,
                   const char *fmt, ...) __attribute__((format(printf, 4, 5)));

/* Hex + ASCII dump written through the logger (used for suspicious blocks). */
void log_hexdump(Logger *lg, const uint8_t *data, size_t size, int max_lines);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_LOGGER_H */
