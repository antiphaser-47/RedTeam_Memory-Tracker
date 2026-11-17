/*
 * platform_linux.h - Linux-only helpers that are not part of the portable
 *                    PlatformOps vtable.
 *
 * main_linux.c calls linux_maps_invalidate() immediately after any mmap /
 * munmap / mprotect so the maps snapshot used by get_perms() stays fresh
 * without paying a /proc read on every single query.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_PLATFORM_LINUX_H
#define TRACKER_PLATFORM_LINUX_H

/* Drop the cached /proc/self/maps snapshot (next lookup reloads it). */
void linux_maps_invalidate(void);

#endif /* TRACKER_PLATFORM_LINUX_H */
