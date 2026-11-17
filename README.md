# CoreSight-Style Real-Time Memory Tracker

Real-time memory behaviour analysis for security research and red-team
exercises, borrowing the *trace → sink → formatter* architecture of ARM
CoreSight: producers (interceptors / kprobes) write into a lock-free trace
sink, a scheduler opens a fixed recording window, and a formatter turns the
captured stream into a human-readable log.

Four deliverables from one code base:

| Deliverable | Target | Privilege | Entry point |
|---|---|---|---|
| `tracker_linux` | Linux x86-64 | user | `make user` |
| `tracker.exe` | Windows x64 | user | `make win` (cross-compiled) |
| `memory_tracker.ko` | Linux kernel | **root** | `make kmod` |
| `libtracker_preload.so` | Linux, any process | user | `make preload` |

Every log line is plain text, grep-able, and tagged with the recording cycle
it belongs to:

```
2026-11-17 17:17:55 [cycle #1] [RWX] RWX region allocated @ 0x00007f65bb27c000 size=4096 perms=0x7 stack=0x67b03dd1759769ae
2026-11-17 17:17:55 [cycle #1] [HOOK] *** inline hook: victim_function -> JMP rel32 (E9) @ 0x5b3a5ff32e90 ***
2026-11-17 17:17:55 [cycle #1] [UAF] *** use-after-free write: 0x00005b3a970f7fd0 size=128 offset+64 expected=0x5A got=0xDE (freed 2991.899 ms before this scan, never reallocated) ***
```

---

## Cadence: scan every 20 s, record for 3 s

```
|-- recording 3 s --|-- scan + report --|------------ idle 17 s ------------|
   events enter ring   drain ring → detect → log      no overhead
   cycle #1            cycle #1                        cycle #2 starts
```

* Only events captured inside the 3-second window are attributed to that
  cycle, so `[cycle #N]` maps to a precise time slice.
* The ring never blocks the allocator: overflow is counted as `dropped`, and
  the statistics guarantee `consumed + dropped == produced`.

---

## Detection coverage

User-space trackers (`tracker_linux` / `tracker.exe`), 6 detectors:

| Tag | What it catches | Severity |
|---|---|---|
| `[RWX]` | Read-write-execute regions (shellcode landing zones) | ALERT |
| `[PERM_CHANGE]` | Page permission flips (RW→RX, RX→RW …) | WARN |
| `[ROP]` | Byte-pattern pre-filter → **Capstone disassembly verification**, executable pages only | ALERT |
| `[RET2LIBC]` | Dangerous libc symbols, `"/bin/sh"`, hijacked function pointers | ALERT |
| `[HOOK]` | Inline hooks on syscall/libc prologues (`E9` JMP detection) | ALERT |
| `[HIGH_ENTROPY]` | Shannon entropy ≥ 7.5 (encrypted/encoded payload) | WARN |
| `[NOP_SLED]` / `[INT3_SLED]` / `[LOW_PRINTABLE]` | Shellcode sleds and packed content | WARN |
| `[UAF]` | Use-after-free **writes**, verified against a pre-free snapshot | ALERT |
| `[DOUBLE_FREE]` | Same pointer released twice | ALERT |
| `[OVERFLOW]` | Redzone overrun with exact offset and expected/actual byte | ALERT |

Kernel module (`memory_tracker.ko`), 10 kprobe/kretprobe hooks on
`__kmalloc*` / `kmem_cache_alloc*` / `kfree` / `kmem_cache_free`:

| Event | Meaning |
|---|---|
| `DOUBLE_FREE` | Pointer released while still in quarantine |
| `WRONG_FREE` | `kfree()` on a `kmem_cache_alloc()` block (or vice versa) |
| `CACHE_MISMATCH` | Released through a different cache than allocated from |
| `OVERSIZE` | Allocation ≥ `oversize_kb` threshold |
| `UNKNOWN_FREE` | Pointer allocated before the module was loaded (informational) |

LD_PRELOAD shim (`libtracker_preload.so`): `[OVERFLOW]` and `[DOUBLE_FREE]`
for **any** binary, without recompiling it.

---

## Quick start

```bash
# build everything user-space
make            # tracker_linux
make win        # tracker.exe  (needs mingw-w64 + bundled Capstone)
make preload    # libtracker_preload.so

# run one full cycle with the 11 built-in detection test cases
./build/tracker_linux --selftest --cycles 1

# watch the log
tail -f memory_tracker.log
```

Kernel module (root required):

```bash
sudo make kmod
sudo insmod build/memory_tracker.ko trace_alloc=0 oversize_kb=1024

D=/sys/kernel/debug/memory_tracker
cat $D/stats        # probe registration table, ring + live-block counters
cat $D/events       # drained trace, symbols resolved
cat $D/selftest     # 6-step self test → result: PASS (6/6)
echo 1 > $D/clear   # drop backlog and reset the live-block table
sudo rmmod memory_tracker
```

LD_PRELOAD shim on an arbitrary program:

```bash
TRACKER_SHIM_LOG=/tmp/shim.log \
LD_PRELOAD=$PWD/build/libtracker_preload.so ./target_program
```

### CLI options

| Option | Default | Meaning |
|---|---|---|
| `--log PATH` | `memory_tracker.log` | log file |
| `--interval N` | `20` | seconds between cycle starts |
| `--record N` | `3` | recording window, seconds |
| `--cycles N` | `0` (wait for Enter) | exit after N completed cycles |
| `--ring N` | `16384` | trace ring slots (rounded to power of two) |
| `--selftest` | off | stage the 11 built-in detection cases |
| `--no-color` | off | disable ANSI colour on the console |

---

## Architecture

```
src/core/      platform-independent core (C11, no OS headers)
               ├── ring_buffer.c      SPSC lock-free ring + per-slot seqlock
               ├── block_table.c      tracked block table (user space)
               ├── scheduler.c        IDLE → RECORDING(3s) → SCAN → sleep
               ├── logger.c           cycle-tagged, colour-coded event log
               └── detector_*.c       rwx / entropy / hook / rop /
                                      ret2libc / heap (UAF, double free, overflow)

src/linux/     platform_linux.c  + main_linux.c   (/proc/self/maps, pthreads)
src/win/       platform_win.c    + main_win.c     (VirtualQuery, Win32)
src/kmod/      ring_kernel.c     per-CPU lock-free ring (IRQ-safe)
               kblock.c          live-block table w/ quarantine
               probes.c          10 kprobe/kretprobe handlers
               debugfs_iface.c   stats / events / clear / selftest
               tracker_kmod.c    module entry, module_param, init order

include/       public headers; OS differences isolated behind PlatformOps
tests/         run_test.sh (46) · test_shim.sh (7) · test_win.ps1 (46)
               test_kmod.sh (15 + 9 load-time) · test_ring.c · test_block_table.c
```

The same core compiles for all three platforms; everything OS-specific lives
behind the `PlatformOps` vtable in `include/platform.h`.

---

## Testing

```bash
make test        # unit + localhost functional + shim  → 46 + 7 assertions
make kmod-test   # module build assertions (+ load test when run as root)
tests/test_win.bat   # on Windows: 46 assertions, same layout as run_test.sh
```

Reports are written to `build/test_report.txt`, `build/shim_test_report.txt`,
`build/kmod_test_report.txt`. Current status:

| Report | Result |
|---|---|
| user-space functional | **PASS=46 FAIL=0** |
| LD_PRELOAD shim | **PASS=7 FAIL=0** |
| kernel module (no root) | **PASS=15 FAIL=0 SKIP=1** |
| Windows (run on Windows) | 46 assertions, not executed on this host |

---

## Documentation

* **[`docs/USAGE.md`](docs/USAGE.md)** — 完整使用手冊（繁體中文）：
  使用方式、事件標籤解讀、`[STATS]` 報告拆解、這些結果可以做什麼、
  誤報與限制、故障排查。
* **[`third_party/README.md`](third_party/README.md)** — how the MinGW
  build of Capstone 4.0.2 was produced.

---

## Packaging

```bash
make package     # → dist/  (3 binaries + .ko + tests + docs)
```

`dist/` is rebuilt from scratch on every run, so stale files never leak into
the bundle.

---

## Limitations

* The user-space trackers only see allocations made by **their own process**
  (plus whatever `LD_PRELOAD` can interpose).
* The recording window is 3 s: activity outside it belongs to the next cycle.
* ROP scanning covers **executable pages only**, and needs Capstone
  (failure is reported as `[ERROR]` and disables just that detector).
* The kernel module covers the `kmalloc` / `kmem_cache` paths listed above;
  `vmalloc` and bulk allocators are not hooked, so their releases surface as
  `UNKNOWN_FREE`.
* Pointers allocated **before** `insmod` are unknown by design — that is why
  `trace_unknown` defaults to off.
* The Windows binary is cross-compiled on Linux and must be verified on a
  Windows host (`tests/test_win.bat`).

## Disclaimer

For authorized security research and red-team exercises only. The tools
inspect and report on their own process (or, for the kernel module, on the
kernel allocator they are explicitly loaded to observe); they do not attack
other systems.
