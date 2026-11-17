/*
 * detector_hook.h
 */
#ifndef TRACKER_DETECTOR_HOOK_H
#define TRACKER_DETECTOR_HOOK_H

#include "detectors.h"

/* Watch an explicit address (dlsym cannot see static functions). */
void hook_watch(const char *name, void *addr);

/* Drop every watched entry (test isolation). */
void hook_reset(void);

void scan_hooks(ScanContext *ctx);

#endif /* TRACKER_DETECTOR_HOOK_H */
