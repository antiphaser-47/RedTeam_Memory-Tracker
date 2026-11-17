/*
 * detector_rwx.h
 */
#ifndef TRACKER_DETECTOR_RWX_H
#define TRACKER_DETECTOR_RWX_H

#include "detectors.h"

void scan_rwx_on_event(ScanContext *ctx, const TraceEvent *ev);
void scan_rwx(ScanContext *ctx);

#endif /* TRACKER_DETECTOR_RWX_H */
