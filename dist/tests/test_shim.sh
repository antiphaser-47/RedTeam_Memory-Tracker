#!/usr/bin/env bash
# ============================================================================
# test_shim.sh - functional verification for libtracker_preload.so
# ----------------------------------------------------------------------------
# WHAT THIS DOES
#   1. compiles a tiny victim program that makes one deliberate mistake of
#      each kind the shim can see (overflow, double free) plus one clean
#      allocation that must stay silent
#   2. runs it under LD_PRELOAD=build/libtracker_preload.so
#   3. asserts the alerts, and asserts the absence of false positives
#   4. writes build/shim_test_report.txt
#
# WHY IT IS A SEPARATE SCRIPT
#   run_test.sh verifies the tracker binary (46 assertions, mirrored on
#   Windows by tests/test_win.ps1).  The shim is Linux-only and is a
#   different deliverable, so it gets its own report instead of changing
#   the tracker's baseline numbers.
#
# EXIT CODE
#   0 = every expectation met, non-zero otherwise
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

SHIM="${SHIM:-build/libtracker_preload.so}"
REPORT="${REPORT:-build/shim_test_report.txt}"
WORK="${WORK:-build/shim_victim}"

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

# check_present <extended-regex> <description>
check_present() {
    if grep -Eq -- "$1" "$OUT" 2>/dev/null; then
        PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("PASS | $2")
    else
        FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("FAIL | $2 (missing: $1)")
    fi
}

# check_absent <extended-regex> <description>
check_absent() {
    if grep -Eq -- "$1" "$OUT" 2>/dev/null; then
        FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("FAIL | $2 (unexpected match: $1)")
    else
        PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("PASS | $2")
    fi
}

# check_num <actual> <expected> <description>
check_num() {
    if [ "$1" = "$2" ]; then
        PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("PASS | $3 (= $1)")
    else
        FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("FAIL | $3 (expected $2, got $1)")
    fi
}

# ---------------------------------------------------------------------------
# 0. preconditions
# ---------------------------------------------------------------------------

if [ ! -f "$SHIM" ]; then
    echo "ERROR: $SHIM not found - run 'make preload' first."
    exit 2
fi

# The victim: three operations, each one a specific expectation.
cat > "${WORK}.c" <<'EOF'
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char *p, *q, *r;

    /* (1) 16-byte block, one byte written past the end -> redzone hit. */
    p = malloc(16);
    memset(p, 'A', 16);
    p[16] = 'X';
    free(p);

    /* (2) same pointer released twice -> double free. */
    q = calloc(4, 4);
    memset(q, 'B', 16);
    free(q);
    free(q);

    /* (3) perfectly well-behaved allocation -> must stay silent. */
    r = realloc(NULL, 32);
    memset(r, 'C', 32);
    r = realloc(r, 8);
    free(r);

    printf("victim done\n");
    return 0;
}
EOF

gcc -O0 -g -o "$WORK" "${WORK}.c" || {
    echo "ERROR: cannot build the victim program"
    exit 2
}

OUT="build/shim_victim_out.txt"
: > "$OUT"

echo "== running: LD_PRELOAD=$SHIM $WORK"
LD_PRELOAD="$PWD/$SHIM" "$WORK" > "$OUT" 2>&1
RC=$?

if [ "$RC" -ne 0 ]; then
    echo "ERROR: victim exited with status $RC (see $OUT)"
    exit 2
fi

# ---------------------------------------------------------------------------
# 1. alerts that must be present
# ---------------------------------------------------------------------------

check_present 'LD_PRELOAD heap guard active' \
              "shim announced itself at startup"

# expected=/got= are printed with %02X, hence the mixed-case hex class.
check_present '\[OVERFLOW\].*redzone overrun \(LD_PRELOAD shim\): block 0x[0-9a-f]+ size=16 offset=0 expected=0x[0-9a-fA-F]+ got=0x58' \
              "overflow reported with the exact offset (0) and the written byte"

check_present '\[DOUBLE_FREE\].*double free \(LD_PRELOAD shim\): 0x[0-9a-f]+ was already freed, block size=16' \
              "double free reported with the block size"

check_present 'victim done' \
              "victim ran to completion (the shim does not crash the target)"

# ---------------------------------------------------------------------------
# 2. false-positive control
# ---------------------------------------------------------------------------

# Exactly one alert of each kind: the well-behaved realloc path must not
# add a second one.
OVF_COUNT="$(grep -c '\[OVERFLOW\]' "$OUT" || true)"
check_num "$OVF_COUNT" "1" "exactly one overflow alert"

DF_COUNT="$(grep -c '\[DOUBLE_FREE\]' "$OUT" || true)"
check_num "$DF_COUNT" "1" "exactly one double-free alert"

# The clean block is the only one of size 32 in the victim.
check_absent 'size=32' "clean 32-byte allocation produced no alert"

# ---------------------------------------------------------------------------
# 3. report
# ---------------------------------------------------------------------------

{
    echo "================================================================"
    echo " libtracker_preload.so functional test report"
    echo " date        : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo " shim        : $SHIM"
    echo " output      : $OUT"
    echo " result      : PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
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
