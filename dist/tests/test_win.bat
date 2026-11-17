@echo off
rem ============================================================================
rem test_win.bat - Windows functional verification entry point
rem ----------------------------------------------------------------------------
rem WHAT THIS DOES
rem   Runs tracker.exe in self-test mode for one scan cycle and asserts, from
rem   the produced log, that every detector fired the way it does on Linux.
rem   The result is written to build\test_report.txt in exactly the same
rem   layout as tests\run_test.sh produces on Linux, so the two reports can
rem   be compared side by side.
rem
rem WHY THERE IS A SECOND FILE
rem   cmd.exe's findstr cannot express the assertions (character classes,
rem   "+", alternation).  The checks therefore live in test_win.ps1, which
rem   uses the same regular expressions as run_test.sh.  This .bat file is
rem   the stable entry point documented in the Makefile and in docs\USAGE.md.
rem
rem USAGE
rem   tests\test_win.bat                 (defaults: build\tracker.exe)
rem   tests\test_win.bat -Bin path\to\tracker.exe -Log out.log
rem
rem EXIT CODE
rem   0 = every expectation met, 1 = at least one failure, 2 = setup error
rem ============================================================================
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%test_win.ps1"

if not exist "%PS1%" (
    echo ERROR: %PS1% not found
    exit /b 2
)

where powershell >nul 2>nul
if errorlevel 1 (
    echo ERROR: Windows PowerShell is required to run this test.
    exit /b 2
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
exit /b %ERRORLEVEL%
