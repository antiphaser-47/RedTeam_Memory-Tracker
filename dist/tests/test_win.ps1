# ============================================================================
# test_win.ps1 - Windows functional verification for tracker.exe
# ----------------------------------------------------------------------------
# WHAT THIS DOES
#   1. runs tracker.exe in self-test mode for exactly one scan cycle
#   2. asserts, by matching the produced log, that every detector fired on
#      the situation it is supposed to notice
#   3. asserts the negative cases too (a benign block must stay clean)
#   4. writes a PASS/FAIL report to build\test_report.txt
#
# WHY POWERSHELL
#   The .bat entry point (tests\test_win.bat) is intentionally thin.  The
#   assertions themselves are regular expressions with + and character
#   classes, which cmd.exe's findstr cannot express; PowerShell's
#   Select-String uses .NET regex, whose syntax is compatible with the
#   extended-regex patterns used by tests/run_test.sh - so both platforms
#   assert literally the same things.
#
# PARITY WITH run_test.sh
#   46 counted assertions, same order, same descriptions, same report
#   layout.  One assertion is Windows specific:
#     - Linux looks for the "/bin/sh" ret2libc argument string in libc;
#       Windows looks for "cmd.exe" in the core runtime module instead and
#       reports it as SKIP when it is absent (that string is not guaranteed
#       to live in ntdll/kernel32, so it must not fail the run).
#
# EXIT CODE
#   0 = every expectation met, 1 = at least one failure, 2 = setup error
# ============================================================================
param(
    [string]$Bin    = "",
    [string]$Log    = "",
    [string]$Report = ""
)

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir   = Split-Path -Parent $ScriptDir
Set-Location $RootDir

if (-not $Bin)    { $Bin    = Join-Path $RootDir "build\tracker.exe" }
if (-not $Log)    { $Log    = Join-Path $RootDir "build\functional_test.log" }
if (-not $Report) { $Report = Join-Path $RootDir "build\test_report.txt" }
$Stdout = Join-Path $RootDir "build\functional_stdout.txt"

# ---------------------------------------------------------------------------
# assertion helpers
# ---------------------------------------------------------------------------

$script:Results   = New-Object System.Collections.ArrayList
$script:PassCount = 0
$script:FailCount = 0

# kind = "present" : fails when the pattern does NOT match
# kind = "absent"  : fails when the pattern DOES match
# kind = "optional": reports SKIP when the pattern does not match
function Add-Check {
    param([string]$Pattern, [string]$Description, [string]$Kind = "present", [string]$Text)

    $matched = $false
    if ($Text) { $matched = [regex]::IsMatch($Text, $Pattern) }

    switch ($Kind) {
        "absent" {
            if ($matched) {
                $script:FailCount++
                [void]$script:Results.Add("FAIL | $Description (unexpected match: $Pattern)")
            } else {
                $script:PassCount++
                [void]$script:Results.Add("PASS | $Description")
            }
        }
        "optional" {
            if ($matched) {
                $script:PassCount++
                [void]$script:Results.Add("PASS | $Description")
            } else {
                [void]$script:Results.Add("SKIP | $Description (not present on this platform)")
            }
        }
        default {
            if ($matched) {
                $script:PassCount++
                [void]$script:Results.Add("PASS | $Description")
            } else {
                $script:FailCount++
                [void]$script:Results.Add("FAIL | $Description (missing: $Pattern)")
            }
        }
    }
}

# Assert that the last occurrence of a two-number pattern matches exactly.
function Add-NumCheck {
    param([string]$Pattern, [string]$Group1Expected, [string]$Group2Expected,
          [string]$Description1, [string]$Description2, [string]$Text)

    $m = [regex]::Matches($Text, $Pattern)
    if ($m.Count -eq 0) {
        $script:FailCount += 2
        [void]$script:Results.Add("FAIL | $Description1 (pattern not found: $Pattern)")
        [void]$script:Results.Add("FAIL | $Description2 (pattern not found: $Pattern)")
        return
    }
    $last = $m[$m.Count - 1]

    $a1 = $last.Groups[1].Value
    if ($a1 -eq $Group1Expected) {
        $script:PassCount++
        [void]$script:Results.Add("PASS | $Description1 (= $a1)")
    } else {
        $script:FailCount++
        [void]$script:Results.Add("FAIL | $Description1 (expected $Group1Expected, got $a1)")
    }

    $a2 = $last.Groups[2].Value
    if ($a2 -eq $Group2Expected) {
        $script:PassCount++
        [void]$script:Results.Add("PASS | $Description2 (= $a2)")
    } else {
        $script:FailCount++
        [void]$script:Results.Add("FAIL | $Description2 (expected $Group2Expected, got $a2)")
    }
}

# Assert that a single-number pattern equals the expected value.
function Add-SingleNumCheck {
    param([string]$Pattern, [string]$Group, [string]$Expected, [string]$Description, [string]$Text)

    $m = [regex]::Matches($Text, $Pattern)
    if ($m.Count -eq 0) {
        $script:FailCount++
        [void]$script:Results.Add("FAIL | $Description (pattern not found: $Pattern)")
        return
    }
    $actual = $m[$m.Count - 1].Groups[[int]$Group].Value
    if ($actual -eq $Expected) {
        $script:PassCount++
        [void]$script:Results.Add("PASS | $Description (= $actual)")
    } else {
        $script:FailCount++
        [void]$script:Results.Add("FAIL | $Description (expected $Expected, got $actual)")
    }
}

# ---------------------------------------------------------------------------
# 0. preconditions
# ---------------------------------------------------------------------------

if (-not (Test-Path $Bin)) {
    Write-Host "ERROR: $Bin not found - run 'make win' first."
    exit 2
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Log) | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $Log, $Report, $Stdout

Write-Host "== running: $Bin --selftest --cycles 1 --log $Log"
& $Bin --selftest --cycles 1 --log $Log --no-color > $Stdout 2>&1
$rc = $LASTEXITCODE

if ($rc -ne 0) {
    Write-Host "ERROR: tracker exited with status $rc (see build\functional_stdout.txt)"
    exit 2
}

if (-not (Test-Path $Log) -or (Get-Item $Log).Length -eq 0) {
    Write-Host "ERROR: log file $Log was not produced"
    exit 2
}

$Text = Get-Content -Path $Log -Raw

# ---------------------------------------------------------------------------
# 1. lifecycle / cadence expectations
# ---------------------------------------------------------------------------

Add-Check 'recording window OPEN \(3 s\)'             "recording window opened for 3 seconds" "present" $Text
Add-Check 'recording window CLOSED \([0-9]+\.[0-9]+ s' "recording window closed with elapsed time" "present" $Text
Add-Check 'cycle summary: drained=[0-9]+ \(in-window=[0-9]+' "cycle summary reports drained in-window events" "present" $Text
Add-Check 'ring-dropped=[0-9]+'                        "ring buffer drop counter reported" "present" $Text
Add-Check 'scheduler thread started'                   "scheduler thread started" "present" $Text
Add-Check 'scheduler thread stopped'                   "scheduler thread stopped cleanly" "present" $Text
Add-Check 'reached 1 completed cycle'                  "one full cycle completed" "present" $Text
Add-Check '---- final summary ----'                    "final summary section present" "present" $Text

# Every ALLOC staged by the self test must be in the log.
Add-Check 'case1: normal 1 KiB block of 0x41'          "case1 staged (benign baseline)" "present" $Text
Add-Check 'case2: 2 KiB of random bytes'               "case2 staged (encrypted payload stand-in)" "present" $Text
Add-Check 'case3: 512-byte NOP sled'                   "case3 staged (NOP sled)" "present" $Text
Add-Check 'case4: RWX page'                            "case4 staged (RWX region)" "present" $Text
Add-Check 'case5: control-byte block'                  "case5 staged (non-printable blob)" "present" $Text
Add-Check 'case6: patched victim_function'             "case6 staged (inline hook)" "present" $Text
Add-Check 'case7: short-lived 64-byte block'           "case7 staged (alloc+free)" "present" $Text
Add-Check 'case8: page flipped RW -> RX'               "case8 staged (permission transition)" "present" $Text
Add-Check 'case9: 48-byte block staged for double free' "case9 staged (double free)" "present" $Text
Add-Check 'case10: 128-byte block staged for use-after-free' "case10 staged (use-after-free)" "present" $Text
Add-Check 'case11: 64-byte block \+ 16-byte redzone'   "case11 staged (redzone overflow)" "present" $Text

# ---------------------------------------------------------------------------
# 2. detector expectations - positive
# ---------------------------------------------------------------------------

Add-Check '\[RWX\] RWX region allocated @ 0x[0-9a-f]+'    "RWX: alert on RWX allocation" "present" $Text
Add-Check '\[RWX\] first 32 byte\(s\) of the RWX region'  "RWX: payload bytes dumped" "present" $Text
Add-Check '58 C3 00 00'                                   "RWX: gadget bytes visible in dump" "present" $Text
Add-Check '\[HIGH_ENTROPY\] entropy [0-9]+\.[0-9]+ > 7\.50' "entropy: high-entropy block flagged" "present" $Text
Add-Check '\[NOP_SLED\] NOP sled of 512 byte\(s\)'         "NOP sled: 512-byte run detected" "present" $Text
Add-Check '\[LOW_PRINTABLE\] only [0-9]+\.[0-9]+% printable' "printable: control-byte block flagged" "present" $Text
Add-Check '\[PERM_CHANGE\] permissions changed @ 0x[0-9a-f]+: 0x3 -> 0x5' "perm change: RW -> RX transition detected" "present" $Text
Add-Check '\[HOOK\] \*\*\* inline hook: victim_function -> JMP rel32 \(E9\)' "hook: real inline patch detected" "present" $Text
Add-Check 'target = 0x[0-9a-f]+ +module = '              "hook: jump target resolved to a module" "present" $Text
Add-Check '\[FREE\] addr=0x[0-9a-f]+ size=64'            "free: released block recorded" "present" $Text
Add-Check 'hook scan: watched=[0-9]+ inline-hooks=1'     "hook: watch list seeded with defaults + victim" "present" $Text

# --- P3 additions: Capstone-verified ROP + ret2libc surface ---
Add-Check '\[ROP\] gadget: pop rax; ret @ 0x[0-9a-f]+'   "ROP: Capstone verified 'pop rax; ret' gadget" "present" $Text
Add-Check '\[ROP\] gadget: pop rdi; ret @ 0x[0-9a-f]+'   "ROP: Capstone verified 'pop rdi; ret' gadget" "present" $Text
Add-Check '\[ROP\] [0-9]+ gadget\(s\) in executable block' "ROP: block-level gadget summary" "present" $Text
Add-Check '\[RET2LIBC\] system @ 0x[0-9a-f]+'            "ret2libc: system() address resolved" "present" $Text
Add-Check '\[RET2LIBC\] ret2libc: runtime module @ 0x[0-9a-f]+' "ret2libc: core runtime module located" "present" $Text
# The argument string itself is not guaranteed to live in ntdll/kernel32, so
# it can never fail the run - it is reported as SKIP when missing.  (Linux
# asserts the equivalent "/bin/sh" line inside libc instead.)
Add-Check '\[RET2LIBC\] "cmd\.exe" string @ 0x[0-9a-f]+' "ret2libc: cmd.exe string located in the runtime module" "optional" $Text
Add-Check 'ret2libc surface mapped: [0-9]+ dangerous symbol' "ret2libc: surface summary produced" "present" $Text

# --- P4 additions: heap lifetime forensics ---
Add-Check '\[DOUBLE_FREE\] \*\*\* double free: 0x[0-9a-f]+ \(size=48\) was already freed [0-9.]+ ms ago' "heap: double free detected with the interval between releases" "present" $Text
Add-Check '\[UAF\] \*\*\* use-after-free write: 0x[0-9a-f]+ size=128 offset\+64 expected=0x5A got=0xDE' "heap: use-after-free write detected with exact offset" "present" $Text
Add-Check '\[OVERFLOW\] \*\*\* redzone overrun: block 0x[0-9a-f]+ redzone 0x[0-9a-f]+ size=16 offset=0 expected=0xCC got=0xEE' "heap: redzone canary overrun detected" "present" $Text
Add-Check 'heap scan: quarantined=[0-9]+ this-cycle uaf=[0-9]+ overflow=[0-9]+' "heap: per-cycle summary produced" "present" $Text
Add-Check 'cumulative uaf=[0-9]+ double-free=[0-9]+ overflow=[0-9]+' "heap: cumulative counters produced" "present" $Text

# ---------------------------------------------------------------------------
# 3. detector expectations - negative (false-positive control)
# ---------------------------------------------------------------------------

# case1 is a plain 0x41 buffer: it must NOT be reported as suspicious.
Add-Check 'size=1024 perms=0x3 entropy=[0-9.]+ hits=\['  "no false positive on the benign 1 KiB block" "absent" $Text

# 7 blocks are tracked: case1-5 + case8 + the case11 redzone block.  Only
# 6 are suspicious - case1 (plain 0x41) and case9/case10 (freed, so already
# gone from the live table) are excluded.
Add-NumCheck 'blocks tracked=(\d+) suspicious=(\d+)' "7" "6" `
             "blocks tracked after self test" "suspicious blocks (benign block excluded)" $Text

# The scan must not have lost any ring events.
Add-SingleNumCheck 'ring: produced=\d+ dropped=(\d+)' "1" "0" `
                   "no ring buffer events dropped" $Text

# Zero-filled padding must not be reported as a gadget: the RWX page in
# case4 is mostly 0x00, so a missing filter would show dozens of
# "add byte ptr [rax], al; ... ; ret" chains.
$ArtifactCount = ([regex]::Matches($Text, 'gadget: add byte ptr \[rax\], al')).Count
if ("$ArtifactCount" -eq "0") {
    $script:PassCount++
    [void]$script:Results.Add("PASS | no zero-fill artifact gadgets reported (= 0)")
} else {
    $script:FailCount++
    [void]$script:Results.Add("FAIL | no zero-fill artifact gadgets reported (expected 0, got $ArtifactCount)")
}

# ---------------------------------------------------------------------------
# 4. report
# ---------------------------------------------------------------------------

$stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
$lines = @()
$lines += "================================================================"
$lines += " tracker.exe functional test report"
$lines += " date        : $stamp"
$lines += " binary      : $Bin"
$lines += " log         : $Log"
$lines += " result      : PASS=$($script:PassCount) FAIL=$($script:FailCount)"
$lines += "================================================================"
$lines += ""
foreach ($r in $script:Results) { $lines += "  $r" }
$lines += ""
$lines += "----------------------------------------------------------------"
if ($script:FailCount -eq 0) { $lines += " OVERALL: PASS" } else { $lines += " OVERALL: FAIL" }
$lines += "================================================================"

$lines | Set-Content -Path $Report -Encoding UTF8

Get-Content -Path $Report | Write-Host
Write-Host ""
Write-Host "report written to $Report"

if ($script:FailCount -ne 0) { exit 1 }
exit 0
