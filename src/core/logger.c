/*
 * logger.c - thread-safe console + file event logger.
 *
 * Output contract (kept stable so test scripts can grep reliably):
 *
 *   <YYYY-MM-DD HH:MM:SS> [cycle #N] [TAG] message        (file, no colour)
 *   <ANSI colour><the same line><reset>                   (console)
 *
 * Colour policy:
 *   red    -> alerts   (hook / ROP / ret2libc / RWX / UAF / double free)
 *   yellow -> warnings (entropy / NOP sled / low printable)
 *   cyan   -> informational scaffolding (scan begin/end, stats)
 *   white  -> normal events (alloc / free)
 * ---------------------------------------------------------------------------
 */
#include "logger.h"

#include <string.h>
#include <time.h>
#include <unistd.h>

/* ANSI colour sequences. */
#define C_RESET  "\033[0m"
#define C_RED    "\033[91m"
#define C_YELLOW "\033[93m"
#define C_CYAN   "\033[96m"
#define C_WHITE  "\033[97m"
#define C_DIM    "\033[90m"

/* Stable event tags.  Indexed by EventType - keep in sync with the enum. */
static const char *const k_event_names[ETYPE__COUNT] = {
    "[NONE]",         /* ETYPE_NONE          = 0  */
    "[ALLOC]",        /* ETYPE_ALLOC         = 1  */
    "[FREE]",         /* ETYPE_FREE          = 2  */
    "[HOOK]",         /* ETYPE_HOOK_DETECT   = 3  */
    "[ROP]",          /* ETYPE_ROP_DETECT    = 4  */
    "[RET2LIBC]",     /* ETYPE_RET2LIBC      = 5  */
    "[RWX]",          /* ETYPE_RWX_ALERT     = 6  */
    "[HIGH_ENTROPY]", /* ETYPE_HIGH_ENTROPY  = 7  */
    "[UAF]",          /* ETYPE_UAF           = 8  */
    "[DOUBLE_FREE]",  /* ETYPE_DOUBLE_FREE   = 9  */
    "[OVERFLOW]",     /* ETYPE_OVERFLOW      = 10 */
    "[PERM_CHANGE]",  /* ETYPE_PERM_CHANGE   = 11 */
    "[NOP_SLED]",     /* ETYPE_NOP_SLED      = 12 */
    "[INT3_SLED]",    /* ETYPE_INT3_SLED     = 13 */
    "[LOW_PRINTABLE]",/* ETYPE_LOW_PRINTABLE = 14 */
    "[SCAN_BEGIN]",   /* ETYPE_SCAN_BEGIN    = 15 */
    "[SCAN_END]",     /* ETYPE_SCAN_END      = 16 */
    "[STATS]",        /* ETYPE_STATS         = 17 */
    "[ERROR]"         /* ETYPE_ERROR         = 18 */
};

static const char *const k_sev_names[5] = {
    "DEBUG", "INFO", "WARN", "ALERT", "CRITICAL"
};

const char *event_type_name(EventType type)
{
    if ((unsigned)type >= (unsigned)ETYPE__COUNT)
        return "[UNKNOWN]";
    return k_event_names[type];
}

const char *severity_name(Severity sev)
{
    if ((unsigned)sev > (unsigned)SEV_CRITICAL)
        return "UNKNOWN";
    return k_sev_names[sev];
}

Severity event_severity(EventType type)
{
    switch (type) {
    case ETYPE_HOOK_DETECT:
    case ETYPE_ROP_DETECT:
    case ETYPE_RET2LIBC:
    case ETYPE_RWX_ALERT:
    case ETYPE_UAF:
    case ETYPE_DOUBLE_FREE:
    case ETYPE_OVERFLOW:
        return SEV_ALERT;

    case ETYPE_HIGH_ENTROPY:
    case ETYPE_NOP_SLED:
    case ETYPE_INT3_SLED:
    case ETYPE_LOW_PRINTABLE:
    case ETYPE_PERM_CHANGE:
        return SEV_WARN;

    case ETYPE_ERROR:
        return SEV_CRITICAL;

    case ETYPE_SCAN_BEGIN:
    case ETYPE_SCAN_END:
    case ETYPE_STATS:
        return SEV_DEBUG;

    default:
        return SEV_INFO;
    }
}

void hit_mask_to_string(uint32_t hit_mask, char *out, size_t out_len)
{
    static const struct { uint32_t bit; const char *name; } k_bits[] = {
        { HIT_RWX,           "RWX"           },
        { HIT_HIGH_ENTROPY,  "HIGH_ENTROPY"  },
        { HIT_ROP,           "ROP"           },
        { HIT_RET2LIBC,      "RET2LIBC"      },
        { HIT_HOOK,          "HOOK"          },
        { HIT_UAF,           "UAF"           },
        { HIT_DOUBLE_FREE,   "DOUBLE_FREE"   },
        { HIT_OVERFLOW,      "OVERFLOW"      },
        { HIT_NOP_SLED,      "NOP_SLED"      },
        { HIT_INT3_SLED,     "INT3_SLED"     },
        { HIT_LOW_PRINTABLE, "LOW_PRINTABLE" },
        { HIT_PERM_CHANGE,   "PERM_CHANGE"   },
    };

    size_t used = 0;
    size_t i;

    if (!out || out_len == 0)
        return;

    out[0] = '\0';

    for (i = 0; i < sizeof(k_bits) / sizeof(k_bits[0]); i++) {
        int n;

        if (!(hit_mask & k_bits[i].bit))
            continue;

        n = snprintf(out + used, out_len - used, "%s%s",
                     used ? "," : "", k_bits[i].name);
        if (n < 0 || (size_t)n >= out_len - used)
            break;                      /* truncated - stop cleanly */
        used += (size_t)n;
    }

    if (out[0] == '\0')
        snprintf(out, out_len, "-");
}

static const char *severity_color(Severity sev)
{
    switch (sev) {
    case SEV_ALERT:
    case SEV_CRITICAL:
        return C_RED;
    case SEV_WARN:
        return C_YELLOW;
    case SEV_DEBUG:
        return C_CYAN;
    default:
        return C_WHITE;
    }
}

int logger_open(Logger *lg, const char *path, int use_color)
{
    if (!lg)
        return -1;

    memset(lg, 0, sizeof(*lg));
    lg->file         = NULL;
    lg->use_color    = use_color ? 1 : 0;
    lg->echo_console = 1;
    lg->cycle        = 0;
    pthread_mutex_init(&lg->lock, NULL);

    if (path) {
        snprintf(lg->path, sizeof(lg->path), "%s", path);
        lg->file = fopen(path, "w");
        if (!lg->file)
            return -1;

        fprintf(lg->file,
                "CoreSight-style Memory Tracker - log file\n"
                "================================================\n\n");
        fflush(lg->file);
    }
    return 0;
}

void logger_close(Logger *lg)
{
    if (!lg)
        return;

    pthread_mutex_lock(&lg->lock);
    if (lg->file) {
        fflush(lg->file);
        fclose(lg->file);
        lg->file = NULL;
    }
    pthread_mutex_unlock(&lg->lock);

    pthread_mutex_destroy(&lg->lock);
}

void logger_set_cycle(Logger *lg, uint64_t cycle, uint64_t window_start_ns)
{
    if (!lg)
        return;
    pthread_mutex_lock(&lg->lock);
    lg->cycle           = cycle;
    lg->window_start_ns = window_start_ns;
    pthread_mutex_unlock(&lg->lock);
}

void logger_flush(Logger *lg)
{
    if (!lg)
        return;
    pthread_mutex_lock(&lg->lock);
    if (lg->file)
        fflush(lg->file);
    fflush(stdout);
    pthread_mutex_unlock(&lg->lock);
}

/* Shared formatting core for log_event / log_event_sev. */
static void log_vprintf(Logger *lg, EventType type, Severity sev,
                        const char *fmt, va_list args)
{
    char timestamp[64];
    char message[1024];
    char cycle_tag[32];
    time_t now;
    struct tm tm_buf;

    if (!lg)
        return;

    now = time(NULL);
    localtime_r(&now, &tm_buf);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);

    vsnprintf(message, sizeof(message), fmt, args);

    if (lg->cycle > 0)
        snprintf(cycle_tag, sizeof(cycle_tag), "[cycle #%llu]",
                 (unsigned long long)lg->cycle);
    else
        cycle_tag[0] = '\0';

    pthread_mutex_lock(&lg->lock);

    if (lg->echo_console) {
        if (lg->use_color)
            printf("%s", severity_color(sev));
        printf("%s %s %s %s\n", timestamp, cycle_tag,
               event_type_name(type), message);
        if (lg->use_color)
            printf("%s", C_RESET);
        fflush(stdout);
    }

    if (lg->file) {
        fprintf(lg->file, "%s %s %s %s\n", timestamp, cycle_tag,
                event_type_name(type), message);
        fflush(lg->file);
    }

    lg->lines_written++;

    pthread_mutex_unlock(&lg->lock);
}

void log_event(Logger *lg, EventType type, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vprintf(lg, type, event_severity(type), fmt, args);
    va_end(args);
}

void log_event_sev(Logger *lg, EventType type, Severity sev,
                   const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vprintf(lg, type, sev, fmt, args);
    va_end(args);
}

void log_hexdump(Logger *lg, const uint8_t *data, size_t size, int max_lines)
{
    size_t i;
    int lines = 0;

    if (!lg || !data || max_lines <= 0)
        return;

    for (i = 0; i < size && lines < max_lines; i += 16) {
        char line[128];
        size_t used = 0;
        int j;
        int n;

        n = snprintf(line, sizeof(line), "    %08zx: ", i);
        if (n < 0)
            break;
        used += (size_t)n;

        for (j = 0; j < 16; j++) {
            if (i + (size_t)j < size)
                n = snprintf(line + used, sizeof(line) - used, "%02X ",
                             data[i + (size_t)j]);
            else
                n = snprintf(line + used, sizeof(line) - used, "   ");
            if (n < 0 || (size_t)n >= sizeof(line) - used)
                break;
            used += (size_t)n;
        }

        n = snprintf(line + used, sizeof(line) - used, "| ");
        if (n > 0)
            used += (size_t)n;

        for (j = 0; j < 16 && i + (size_t)j < size; j++) {
            uint8_t c = data[i + (size_t)j];
            if (used + 1 >= sizeof(line))
                break;
            line[used++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        line[used] = '\0';

        pthread_mutex_lock(&lg->lock);
        if (lg->echo_console)
            printf("%s\n", line);
        if (lg->file) {
            fprintf(lg->file, "%s\n", line);
            fflush(lg->file);
        }
        pthread_mutex_unlock(&lg->lock);

        lines++;
    }
}
