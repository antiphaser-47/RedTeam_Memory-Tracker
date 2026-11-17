#!/usr/bin/env bash
# ============================================================================
# test_kmod.sh - verification for memory_tracker.ko
# ----------------------------------------------------------------------------
# WHAT THIS DOES
#   1. build-time assertions: the module exists, is an x86-64 ELF object,
#      carries the GPL license and the expected module name, references the
#      kprobe API it depends on, and exposes the debugfs path plus the
#      module parameters documented in docs/USAGE.md
#   2. load-time assertions - ONLY when running as root (insmod needs CAP_
#      SYS_MODULE): load the module, read stats/events/selftest through
#      debugfs, then unload it cleanly
#   3. when not root the load half is reported as SKIP, never as a failure,
#      so the script stays green in an unprivileged CI/dev shell
#   4. writes build/kmod_test_report.txt
#
# WHY IT IS A SEPARATE SCRIPT
#   run_test.sh covers the user-space tracker (46 assertions), test_shim.sh
#   covers the LD_PRELOAD shim (7 assertions).  The kernel module needs root
#   and a matching kernel build tree, so it gets its own report and can be
#   skipped independently.
#
# EXIT CODE
#   0 = every executed expectation met (skips do not fail), non-zero otherwise
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

KO="${KO:-build/memory_tracker.ko}"
REPORT="${REPORT:-build/kmod_test_report.txt}"
DEBUGFS_DIR="/sys/kernel/debug/memory_tracker"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS=()

pass() { PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("PASS | $1"); }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("FAIL | $1"); }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); RESULTS+=("SKIP | $1"); }

# check_present <extended-regex> <description> <file>
check_present() {
    if grep -Eq -- "$1" "$3" 2>/dev/null; then
        pass "$2"
    else
        fail "$2 (missing: $1 in $3)"
    fi
}

# ---------------------------------------------------------------------------
# 0. preconditions
# ---------------------------------------------------------------------------

if [ ! -f "$KO" ]; then
    echo "ERROR: $KO not found - run 'make kmod' first."
    exit 2
fi

# ---------------------------------------------------------------------------
# 1. build-time assertions
# ---------------------------------------------------------------------------

# (1) the artefact is an ELF relocatable object produced by kbuild
if file "$KO" | grep -Eq 'ELF 64-bit.*relocatable'; then
    pass "ko is an ELF 64-bit relocatable object"
else
    fail "ko is an ELF 64-bit relocatable object (got: $(file -b "$KO"))"
fi

# (2) modinfo: license, name and version - required for a GPL-only module.
#     `modinfo` prints "key:        value"; fall back to dumping the raw
#     .modinfo section when the tool is unavailable.
MODINFO_OUT="build/kmod_modinfo.txt"
modinfo "$KO" > "$MODINFO_OUT" 2>/dev/null || \
    strings -a -j .modinfo "$KO" > "$MODINFO_OUT" 2>/dev/null || true

check_present '^(license: *)?GPL$'        "modinfo license=GPL"        "$MODINFO_OUT"
check_present '^(name: *)?memory_tracker$' "modinfo name=memory_tracker" "$MODINFO_OUT"
check_present 'memory tracker' \
    "modinfo description mentions the memory tracker" "$MODINFO_OUT"

# (3) the symbols the module depends on: probe registration and the debugfs
#     path.  Both are dynamic dependencies (shown by `nm -u`) plus literal
#     strings baked into the binary.
NM_OUT="build/kmod_nm.txt"
nm -u "$KO" > "$NM_OUT" 2>/dev/null || true

check_present 'register_kretprobe'   "depends on register_kretprobe"   "$NM_OUT"
check_present 'register_kprobe'      "depends on register_kprobe"      "$NM_OUT"
check_present 'unregister_kretprobe' "depends on unregister_kretprobe" "$NM_OUT"

# (4) literal strings: the debugfs interface and the documented parameters
STR_OUT="build/kmod_strings.txt"
strings -a "$KO" > "$STR_OUT" 2>/dev/null || true

check_present '/sys/kernel/debug/memory_tracker' \
    "announces the debugfs path at load time" "$STR_OUT"
check_present 'memory_tracker: ' "log messages are prefixed with the module name" \
    "$STR_OUT"
check_present 'ring_size'          "exposes the ring_size parameter"    "$STR_OUT"
check_present 'kblock_bits'        "exposes the kblock_bits parameter"  "$STR_OUT"
check_present 'oversize_kb'        "exposes the oversize_kb parameter"  "$STR_OUT"
check_present 'trace_alloc'        "exposes the trace_alloc parameter"  "$STR_OUT"

# (5) the debugfs entry points must be among the undefined (imported) symbols
check_present 'debugfs_create_dir'  "imports debugfs_create_dir"  "$NM_OUT"
check_present 'sprint_symbol'       "imports sprint_symbol (GPL)" "$NM_OUT"

# ---------------------------------------------------------------------------
# 2. load-time assertions (root only)
# ---------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    skip "module load test (requires root: sudo make kmod-test)"
elif [ ! -d /sys/kernel/debug ]; then
    skip "module load test (debugfs not mounted)"
else
    # Make sure we start from a clean state in case a previous run leaked.
    rmmod memory_tracker 2>/dev/null || true

    if ! insmod "$KO" 2>build/kmod_insmod_err.txt; then
        fail "insmod $KO (see build/kmod_insmod_err.txt)"
    else
        pass "insmod $KO succeeded"

        # The debugfs directory must exist immediately after loading.
        if [ -d "$DEBUGFS_DIR" ]; then
            pass "debugfs directory $DEBUGFS_DIR created"
        else
            fail "debugfs directory $DEBUGFS_DIR created"
        fi

        # stats must report a non-zero probe count and a sane ring config
        STATS_OUT="build/kmod_stats.txt"
        cat "$DEBUGFS_DIR/stats" > "$STATS_OUT" 2>/dev/null || true
        check_present 'registered_ok *: 1[0-9]' \
            "all 10 probes registered (registered_ok >= 10)" "$STATS_OUT"
        check_present 'registration_failed *: 0' \
            "no probe registration failures" "$STATS_OUT"
        check_present 'slots_per_cpu *: 16384' \
            "ring_size parameter reached kring_init (16384 slots)" "$STATS_OUT"

        # The self test runs a real kmalloc/kfree pair and drives the
        # double-free classifier directly; it must report 6/6.
        SELF_OUT="build/kmod_selftest.txt"
        cat "$DEBUGFS_DIR/selftest" > "$SELF_OUT" 2>/dev/null || true
        check_present 'result: PASS \(6/6\)' \
            "debugfs selftest passed 6/6" "$SELF_OUT"
        check_present '\[4\] second release classified *: KBF_DOUBLE_FREE' \
            "double-free classification works" "$SELF_OUT"

        # Generating traffic then draining events must yield at least the
        # selftest marker and the alloc/free pair it performed.
        dd if=/dev/zero of=/dev/null bs=4096 count=64 2>/dev/null || true
        EV_OUT="build/kmod_events.txt"
        cat "$DEBUGFS_DIR/events" > "$EV_OUT" 2>/dev/null || true
        if grep -Eq 'type=SELFTEST' "$EV_OUT"; then
            pass "events file drains the selftest marker"
        else
            fail "events file drains the selftest marker"
        fi
        if grep -Eq 'type=ALLOC' "$EV_OUT"; then
            pass "events file contains allocation records"
        else
            fail "events file contains allocation records"
        fi

        # `clear` must empty the backlog without error.
        if echo 1 > "$DEBUGFS_DIR/clear" 2>/dev/null; then
            pass "clear file accepts a write"
        else
            fail "clear file accepts a write"
        fi

        # Clean unload: module must leave no trace behind.
        if rmmod memory_tracker 2>build/kmod_rmmod_err.txt; then
            pass "rmmod memory_tracker succeeded"
        else
            fail "rmmod memory_tracker succeeded (see build/kmod_rmmod_err.txt)"
        fi

        if [ ! -d "$DEBUGFS_DIR" ]; then
            pass "debugfs directory removed on unload"
        else
            fail "debugfs directory removed on unload"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 3. report
# ---------------------------------------------------------------------------

{
    echo "================================================================"
    echo " memory_tracker.ko test report"
    echo " date        : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo " kernel      : $(uname -r)"
    echo " module      : $KO"
    echo " root        : $([ "$(id -u)" -eq 0 ] && echo yes || echo no)"
    echo " result      : PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT"
    echo "================================================================"
    echo
    for line in "${RESULTS[@]}"; do
        echo "  $line"
    done
    echo
    echo "----------------------------------------------------------------"
    if [ "$FAIL_COUNT" -eq 0 ]; then
        echo " OVERALL: PASS"
    else
        echo " OVERALL: FAIL"
    fi
    echo "================================================================"
} > "$REPORT"

cat "$REPORT"
echo
echo "report written to $REPORT"

[ "$FAIL_COUNT" -eq 0 ] || exit 1
exit 0
