#!/usr/bin/env bash
# ============================================================================
# run_test.sh - localhost functional verification for tracker_linux
# ----------------------------------------------------------------------------
# WHAT THIS DOES
#   1. runs the tracker in self-test mode for exactly one scan cycle
#   2. asserts, by grepping the produced log, that every detector fired on
#      the situation it is supposed to notice
#   3. asserts the negative cases too (a benign block must stay clean)
#   4. writes a PASS/FAIL report to build/test_report.txt
#
# WHY A REPORT FILE
#   The same expectations are mirrored in tests/test_win.bat so the Windows
#   build can be compared against this reference result.
#
# EXIT CODE
#   0 = every expectation met, non-zero otherwise
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

BIN="${BIN:-build/tracker_linux}"
LOG="${LOG:-build/functional_test.log}"
REPORT="${REPORT:-build/test_report.txt}"

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

# ---------------------------------------------------------------------------
# assertion helpers
# ---------------------------------------------------------------------------

# check_present <extended-regex> <description>
# Fails when the regex does NOT appear in the log.
check_present() {
    local pattern="$1"
    local desc="$2"

    if grep -Eq -- "$pattern" "$LOG" 2>/dev/null; then
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS+=("PASS | $desc")
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS+=("FAIL | $desc (missing: $pattern)")
    fi
}

# check_absent <extended-regex> <description>
# Fails when the regex DOES appear in the log.
check_absent() {
    local pattern="$1"
    local desc="$2"

    if grep -Eq -- "$pattern" "$LOG" 2>/dev/null; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS+=("FAIL | $desc (unexpected match: $pattern)")
    else
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS+=("PASS | $desc")
    fi
}

# check_num <actual> <expected> <description>
check_num() {
    local actual="$1" expected="$2" desc="$3"

    if [ "$actual" = "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS+=("PASS | $desc (= $actual)")
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS+=("FAIL | $desc (expected $expected, got $actual)")
    fi
}

# ---------------------------------------------------------------------------
# 0. preconditions
# ---------------------------------------------------------------------------

if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN not found or not executable - run 'make user' first."
    exit 2
fi

mkdir -p "$(dirname "$LOG")"
rm -f "$LOG" "$REPORT"

echo "== running: $BIN --selftest --cycles 1 --log $LOG"
"$BIN" --selftest --cycles 1 --log "$LOG" --no-color > build/functional_stdout.txt 2>&1
RC=$?

if [ "$RC" -ne 0 ]; then
    echo "ERROR: tracker exited with status $RC (see build/functional_stdout.txt)"
    exit 2
fi

if [ ! -s "$LOG" ]; then
    echo "ERROR: log file $LOG was not produced"
    exit 2
fi

# ---------------------------------------------------------------------------
# 1. lifecycle / cadence expectations
# ---------------------------------------------------------------------------

check_present 'recording window OPEN \(3 s\)'            "recording window opened for 3 seconds"
check_present 'recording window CLOSED \([0-9]+\.[0-9]+ s' "recording window closed with elapsed time"
check_present 'cycle summary: drained=[0-9]+ \(in-window=[0-9]+' "cycle summary reports drained in-window events"
check_present 'ring-dropped=[0-9]+'                       "ring buffer drop counter reported"
check_present 'scheduler thread started'                  "scheduler thread started"
check_present 'scheduler thread stopped'                 "scheduler thread stopped cleanly"
check_present 'reached 1 completed cycle'                 "one full cycle completed"
check_present '---- final summary ----'                   "final summary section present"

# Every ALLOC staged by the self test must be in the log.
check_present 'case1: normal 1 KiB block of 0x41'         "case1 staged (benign baseline)"
check_present 'case2: 2 KiB of random bytes'              "case2 staged (encrypted payload stand-in)"
check_present 'case3: 512-byte NOP sled'                  "case3 staged (NOP sled)"
check_present 'case4: RWX page'                           "case4 staged (RWX region)"
check_present 'case5: control-byte block'                 "case5 staged (non-printable blob)"
check_present 'case6: patched victim_function'            "case6 staged (inline hook)"
check_present 'case7: short-lived 64-byte block'          "case7 staged (alloc+free)"
check_present 'case8: page flipped RW -> RX'              "case8 staged (permission transition)"
check_present 'case9: 48-byte block staged for double free' "case9 staged (double free)"
check_present 'case10: 128-byte block staged for use-after-free' "case10 staged (use-after-free)"
check_present 'case11: 64-byte block \+ 16-byte redzone'  "case11 staged (redzone overflow)"

# ---------------------------------------------------------------------------
# 2. detector expectations - positive
# ---------------------------------------------------------------------------

check_present '\[RWX\] RWX region allocated @ 0x[0-9a-f]+'   "RWX: alert on RWX allocation"
check_present '\[RWX\] first 32 byte\(s\) of the RWX region' "RWX: payload bytes dumped"
check_present '58 C3 00 00'                                 "RWX: gadget bytes visible in dump"
check_present '\[HIGH_ENTROPY\] entropy [0-9]+\.[0-9]+ > 7\.50' "entropy: high-entropy block flagged"
check_present '\[NOP_SLED\] NOP sled of 512 byte\(s\)'       "NOP sled: 512-byte run detected"
check_present '\[LOW_PRINTABLE\] only [0-9]+\.[0-9]+% printable' "printable: control-byte block flagged"
check_present '\[PERM_CHANGE\] permissions changed @ 0x[0-9a-f]+: 0x3 -> 0x5' "perm change: RW -> RX transition detected"
check_present '\[HOOK\] \*\*\* inline hook: victim_function -> JMP rel32 \(E9\)' "hook: real inline patch detected"
check_present 'target = 0x[0-9a-f]+ +module = '             "hook: jump target resolved to a module"
check_present '\[FREE\] addr=0x[0-9a-f]+ size=64'           "free: released block recorded"
check_present 'hook scan: watched=[0-9]+ inline-hooks=1'    "hook: watch list seeded with defaults + victim"

# --- P3 additions: Capstone-verified ROP + ret2libc surface ---
check_present '\[ROP\] gadget: pop rax; ret @ 0x[0-9a-f]+'  "ROP: Capstone verified 'pop rax; ret' gadget"
check_present '\[ROP\] gadget: pop rdi; ret @ 0x[0-9a-f]+'  "ROP: Capstone verified 'pop rdi; ret' gadget"
check_present '\[ROP\] [0-9]+ gadget\(s\) in executable block' "ROP: block-level gadget summary"
check_present '\[RET2LIBC\] system @ 0x[0-9a-f]+'           "ret2libc: system() address resolved"
check_present '\[RET2LIBC\] "/bin/sh" string @ 0x[0-9a-f]+' "ret2libc: /bin/sh string located in libc"
check_present 'ret2libc surface mapped: [0-9]+ dangerous symbol' "ret2libc: surface summary produced"

# --- P4 additions: heap lifetime forensics ---
check_present '\[DOUBLE_FREE\] \*\*\* double free: 0x[0-9a-f]+ \(size=48\) was already freed [0-9.]+ ms ago' "heap: double free detected with the interval between releases"
check_present '\[UAF\] \*\*\* use-after-free write: 0x[0-9a-f]+ size=128 offset\+64 expected=0x5A got=0xDE' "heap: use-after-free write detected with exact offset"
check_present '\[OVERFLOW\] \*\*\* redzone overrun: block 0x[0-9a-f]+ redzone 0x[0-9a-f]+ size=16 offset=0 expected=0xCC got=0xEE' "heap: redzone canary overrun detected"
check_present 'heap scan: quarantined=[0-9]+ this-cycle uaf=[0-9]+ overflow=[0-9]+' "heap: per-cycle summary produced"
check_present 'cumulative uaf=[0-9]+ double-free=[0-9]+ overflow=[0-9]+' "heap: cumulative counters produced"

# ---------------------------------------------------------------------------
# 3. detector expectations - negative (false-positive control)
# ---------------------------------------------------------------------------

# case1 is a plain 0x41 buffer: it must NOT be reported as suspicious.
check_absent 'size=1024 perms=0x3 entropy=[0-9.]+ hits=\['  "no false positive on the benign 1 KiB block"

# 7 blocks are tracked: case1-5 + case8 + the case11 redzone block.  Only
# 6 are suspicious - case1 (plain 0x41) and case9/case10 (freed, so already
# gone from the live table) are excluded.
SUSPICIOUS_LINE="$(grep -o 'blocks tracked=[0-9]* suspicious=[0-9]*' "$LOG" | tail -1)"
ACTUAL_TRACKED="$(echo "$SUSPICIOUS_LINE" | sed -n 's/.*tracked=\([0-9]*\).*/\1/p')"
ACTUAL_SUSPICIOUS="$(echo "$SUSPICIOUS_LINE" | sed -n 's/.*suspicious=\([0-9]*\).*/\1/p')"
check_num "$ACTUAL_TRACKED"    "7" "blocks tracked after self test"
check_num "$ACTUAL_SUSPICIOUS" "6" "suspicious blocks (benign block excluded)"

# The scan must not have lost any ring events.
DROPPED_LINE="$(grep -o 'ring: produced=[0-9]* dropped=[0-9]*' "$LOG" | tail -1)"
ACTUAL_DROPPED="$(echo "$DROPPED_LINE" | sed -n 's/.*dropped=\([0-9]*\).*/\1/p')"
check_num "$ACTUAL_DROPPED" "0" "no ring buffer events dropped"

# Zero-filled padding must not be reported as a gadget: the RWX page in
# case4 is mostly 0x00, so a missing filter would show dozens of
# "add byte ptr [rax], al; ... ; ret" chains.
ARTIFACT_COUNT="$(grep -c 'gadget: add byte ptr \[rax\], al' "$LOG" || true)"
check_num "$ARTIFACT_COUNT" "0" "no zero-fill artifact gadgets reported"

# ---------------------------------------------------------------------------
# 4. report
# ---------------------------------------------------------------------------

{
    echo "================================================================"
    echo " tracker_linux functional test report"
    echo " date        : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo " binary      : $BIN"
    echo " log         : $LOG"
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
