# memory-tracker 使用手冊（USAGE）

> 本文件說明本專案四個交付物的**使用方式**、**log 結果如何解讀**，
> 以及**這些結果可以拿來做什麼**。全程以繁體中文說明；
> 程式註解、腳本、log 標籤維持英文（方便 grep 與跨平台比對）。

---

## 0. 交付物總覽

| 交付物 | 產物 | 平台 | 需要權限 | 說明 |
|---|---|---|---|---|
| 主追蹤器 | `build/tracker_linux` | Linux x86-64 | 一般使用者 | 每 20 秒一個週期：錄製 3 秒 → 掃描 → 休息 17 秒 |
| 主追蹤器 | `build/tracker.exe` | Windows x64 | 一般使用者 | 與 Linux 相同 flow，交叉編譯產出（本機不實測） |
| 內核模組 | `build/memory_tracker.ko` | Linux kernel | **root** | kprobe/kretprobe 追蹤 `kmalloc`/`kfree`，經 debugfs 輸出 |
| 堆積守衛 | `build/libtracker_preload.so` | Linux | 一般使用者 | `LD_PRELOAD` 攔截任意程式的 `malloc/free`，抓 overflow / double free |

建置指令（專案根目錄）：

```bash
make            # tracker_linux
make win        # tracker.exe（需要 mingw-w64 與 third_party/capstone）
make preload    # libtracker_preload.so
make kmod       # memory_tracker.ko（需要 kernel headers）
make test       # unit + functional + shim（46 + 7 斷言）
make kmod-test  # kmod 編譯層斷言；有 root 才會載入實測
make package    # 全部打包到 dist/
```

---

## 1. 主追蹤器使用方式

### 1.1 基本用法

```bash
# Linux：預設每 20 秒一個週期、每次錄製 3 秒，log 寫到 memory_tracker.log
./build/tracker_linux

# 只跑一個完整週期就結束（適合排程器或 CI）
./build/tracker_linux --cycles 1

# 直接跑 11 條內建偵測案例（不等週期，用來驗證偵測器本身）
./build/tracker_linux --selftest --cycles 1

# Windows（由使用者自行在 Windows 上執行）
tracker.exe --cycles 1
```

### 1.2 參數

| 參數 | 預設 | 意義 |
|---|---|---|
| `--log PATH` | `memory_tracker.log` | log 檔路徑 |
| `--interval N` | `20` | 兩個週期起點之間的秒數 |
| `--record N` | `3` | 每個週期的錄製視窗秒數（視窗內產生的事件才算進本週期） |
| `--cycles N` | `0`（= 按 Enter 才結束） | 完成 N 個週期後自動退出 |
| `--first-delay N` | `0` | 首次錄製前先延遲 N 秒 |
| `--ring N` | `16384` | 環形緩衝區格數（會自動升到 2 的冪次） |
| `--selftest` | 關 | 啟動時佈建 11 條自測案例 |
| `--no-color` | 關 | 關閉 console 的 ANSI 顏色（寫進檔案的永遠無顏色） |

### 1.3 程式時序（CoreSight 概念借鏡）

```
|--錄製 3s--|--掃描+輸出--|---------睡 17 s---------|
   ↑ 事件進 ring        ↑ 排空 ring → 偵測 → 寫 log
cycle #1               cycle #1                 cycle #2
```

* **錄製視窗**：只有視窗內被攔截到的分配/釋放事件才會進本週期的事件流，
  這樣 log 的 `[cycle #N]` 標籤才有意義（可對應到明確的 3 秒時間段）。
* **掃描**：視窗關閉後，排空 ring、對快照執行 6 組偵測器、寫出結果，
  然後才進入休息，確保 20 秒週期是「起點到起點」。
* **背壓**：ring 滿了不阻塞分配，只累加 `dropped`，
  統計列保證 `consumed + dropped == produced`。

---

## 2. log 欄位與事件標籤解讀

### 2.1 行格式

```
YYYY-MM-DD HH:MM:SS [cycle #N] [TAG] 訊息
```

* 檔案內**沒有顏色碼**，console 才有：
  **紅＝ALERT**（hook / ROP / ret2LIBC / RWX / UAF / double free / overflow）、
  **黃＝WARN**（entropy / NOP sled / INT3 sled / low printable / perm change）、
  **青＝掃描腳手架**（SCAN_BEGIN / SCAN_END / STATS）、
  **白＝一般事件**（ALLOC / FREE）。
* `[cycle #N]` 是週期編號，方便把事件對回「第幾次 3 秒錄製視窗」。

### 2.2 事件標籤一覽

#### 記錄類（INFO，正常運作的痕跡）

| 標籤 | 意義 | 解讀方式 |
|---|---|---|
| `[ALLOC]` | 記錄到一筆記憶體分配 | `addr` 位址、`size` 位元組、`perms` mmap 權限、`stack` 呼叫堆疊雜湊、`ip` 呼叫點 |
| `[FREE]` | 記錄到一筆釋放 | `aux` 欄位攜帶存活時間（ms） |
| `[SCAN_BEGIN]` | 錄製視窗開啟 / 掃描開始 | 週期邊界 |
| `[SCAN_END]` | 錄製視窗關閉 / 掃描結束 | 會附上實際經過秒數（例 `3.002 s`） |

#### 偵測類（ALERT / WARN，需要看的）

| 標籤 | 嚴重度 | 意義與判讀重點 |
|---|---|---|
| `[RWX]` | ALERT | 出現**可讀可寫可執行**的記憶體區塊。這是 shellcode 注入的經典特徵。注意 `perms=0x7`；若區塊內容前 32 byte 出現在 log 的 hexdump 裡，可直接看它是不是 gadget |
| `[PERM_CHANGE]` | WARN | 同一位址的權限被改了（例 `0x3 -> 0x5`，RW→RX）。單次屬正常 JIT/dlopen 行為；反覆翻轉才可疑 |
| `[ROP]` | ALERT | 在**可執行**區塊裡用 Capstone 反組譯驗證出 ROP gadget。`score` 越高代表該區塊越像 gadget 倉庫；`first="..."` 是第一個命中的 gadget 名稱 |
| `[RET2LIBC]` | ALERT / DEBUG | 盤點 libc 危險函式（`system`、`execve`、`mprotect`…）與 `"/bin/sh"` 字串的位置。**關鍵警訊**是 `*** ... is SET -> 0x... ***`（hook 指標被改寫）與 `*** ... resolves OUTSIDE the core runtime module ***`（解析位置跑出 runtime 之外） |
| `[HOOK]` | ALERT / DEBUG | 函式 prologue 被改寫。`*** inline hook: X -> JMP rel32 (E9) @ ... ***` 是被掛鉤；`X: clean (F3 0F 1E FA ..)` 是乾淨的 `endbr64`。結尾的 `hook scan: watched=14 inline-hooks=1 redirected=2 unreadable=0` 是本週期總結 |
| `[HIGH_ENTROPY]` | WARN | Shannon 熵超過門檻（預設 7.5，滿分 8）。可能是加密/編碼後的 payload；壓縮檔、加密金鑰、隨機數也會誤報 |
| `[NOP_SLED]` | WARN | 大片 `0x90`/`0xCC` 連續墊片，shellcode 的著陸區特徵 |
| `[INT3_SLED]` | WARN | 大片 `0xCC`（int3）墊片 |
| `[LOW_PRINTABLE]` | WARN | 大量不可列印控制字元，常見於 packed/混淆後的資料 |
| `[UAF]` | ALERT | **釋放後寫入**：位址已釋放但未被重新分配，掃描時發現內容與釋放前快照不一致。`offset+N expected=0x.. got=0x..` 給出精確偏移與預期/實際值 |
| `[DOUBLE_FREE]` | ALERT | 同一位址被釋放兩次，`was already freed X ms ago` 給出間隔 |
| `[OVERFLOW]` | ALERT | 寫越界到 redzone。`block`/`redzone` 位址、`size`、`offset`、`expected/got` 一次給齊，可直接定位到程式哪一行 |

#### 診斷類（DEBUG / CRITICAL）

| 標籤 | 意義 |
|---|---|
| `[STATS]` | 每週期統計與最終摘要（見 §4） |
| `[ERROR]` | 嚴重錯誤，例如 Capstone 初始化失敗（ROP 偵測器會自動停用並留一條紀錄） |

### 2.3 常見 log 範例逐行拆解

```
2026-11-17 17:17:55 [cycle #1] [RWX] RWX region allocated @ 0x00007f65bb27c000 size=4096 perms=0x7 stack=0x67b03dd1759769ae
```
→ 第 1 週期，某次分配拿到 4 KiB 的 RWX 頁。`stack` 是呼叫堆疊的 FNV-1a 雜湊，
**相同分配路徑會得到相同值**，可用來把多筆告警歸納成同一個源頭。

```
2026-11-17 17:17:55 [cycle #1] [HOOK] *** inline hook: victim_function -> JMP rel32 (E9) @ 0x5b3a5ff32e90 ***
2026-11-17 17:17:55 [cycle #1] [HOOK]     target = 0x00005b3a5ff32e95  module = .../tracker_linux
2026-11-17 17:17:55 [cycle #1] [HOOK]     prologue: E9 00 00 00 00 0D 26 2E 02 00 ...
```
→ 函式前 5 byte 被換成 `E9`（相對跳轉），並附上跳轉目標與改寫後的 16 byte prologue。
`module` 欄位告訴你跳到了哪個映像——**跳回自己映像通常是自掛鉤/匯入表替換，
跳到匿名映射或陌生 .so 才是典型惡意注入**。

```
2026-11-17 17:17:55 [cycle #1] [UAF] *** use-after-free write: 0x00005b3a970f7fd0 size=128 offset+64 expected=0x5A got=0xDE (freed 2991.899 ms before this scan, never reallocated) ***
```
→ 位址已釋放近 3 秒、期間**未被重新分配**，但 offset 64 處的 byte 從 `0x5A` 變成 `0xDE`。
「never reallocated」代表這不是 allocator 重用造成的雜訊，是真實的 UAF 寫入。

```
2026-11-17 17:17:55 [cycle #1] [ROP] 2 gadget(s) in executable block @ 0x00007f65bb27c000 size=4096 first="pop rax; ret"
```
→ 該 RWX 區塊裡找到 2 個經 Capstone 驗證的 gadget。
**byte-pattern 只是初篩，能印出這行代表已經過反組譯精篩**，誤報率遠低於純比對。

---

## 3. 這些結果可以做什麼

1. **惡意行為取證與歸因**
   * 用 `stack` 雜湊把多筆 `[RWX]`／`[ROP]` 告警聚類，找出「少數幾個呼叫點」；
   * 用 `[HOOK] target/module` 判斷掛鉤是自家改寫還是外部注入；
   * 用 `[RET2LIBC]` 的 `is SET` / `OUTSIDE` 判斷攻擊者是否已取得「改寫函式指標」的能力。

2. **漏洞驗證（紅隊 / CTF）**
   * `[OVERFLOW]` 的 `offset` + `expected/got` 直接告訴你越界寫了幾位元、寫了什麼，
     可反推 payload 是否如預期落地；
   * `[DOUBLE_FREE]` 與 `[UAF]` 用來確認 heap 操縱原語是否真的成立。

3. **回歸防護**
   * 以 `--cycles N` 跑固定週期，把 log 當作 CI 產物：
     `grep -c '\[ALERT 類標籤\]' memory_tracker.log` 應為 0；
   * `[STATS] blocks tracked=... suspicious=...` 的 suspicious 數量一旦上升即回歸。

4. **弱點掃描（自我健檢）**
   * `--selftest` 的 11 條案例是**可控的正樣本**，可用來確認偵測器在這台機器上有效；
   * kernel 模組的 `selftest` 檔（§5.3）同理。

5. **即時監控**
   * 主追蹤器的 20 秒週期讓你可以把 log 接到 `tail -f`、SIEM 或 cron 收集器，
     用 `[cycle #N]` 對齊時間軌跡。

---

## 4. `[STATS]` 報告解讀

### 4.1 週期統計

```
[STATS] cycle summary: drained=13 (in-window=13, out-of-window=0) still-buffered=0 ring-dropped=0 blocks=7
```

| 欄位 | 意義 | 異常判斷 |
|---|---|---|
| `drained` | 本週期從 ring 排空的事件數 | 與 `in-window + out-of-window` 相等即一致 |
| `in-window` | 落在 3 秒錄製視窗內 | 遠小於 `drained` 表示事件多產生在視窗外（可能 interval 調太短） |
| `ring-dropped` | 因 ring 滿而丟棄 | **持續 > 0 表示 `--ring` 太小**，請調大 |
| `blocks` | 本週期追蹤中的區塊數 | — |

```
[STATS] heap scan: quarantined=3 this-cycle uaf=1 overflow=1 cumulative uaf=1 double-free=1 overflow=1 reuse=0 redzones=64
[STATS] content scan: new high-entropy=1 nop-sled=1 int3-sled=0 low-printable=1
[STATS] hook scan: watched=14 inline-hooks=1 redirected=2 unreadable=0
[STATS] ROP scan: executable blocks=2 flagged=1
```

* `cumulative *` 是**累計**值，用來看長期趨勢；`this-cycle` 是本週期新增。
* `redzones=64` 表示目前有 64 個區塊掛著紅zone（有 redzone 才能抓 overflow）。
* `unreadable=0` 若 > 0，代表有區塊在掃描時讀不到（可能已被 unmap），
  **這會讓該區塊的偵測結果不完整**，需注意。

### 4.2 最終摘要

```
[STATS] ---- final summary ----
[STATS] 0x00005b3a970f8090 size=80 perms=0x3 entropy=0.86 hits=[OVERFLOW] tag="OVERFLOW" stack=0xc9ae1478d0516ba5
[STATS] 0x00007f65bb27c000 size=4096 perms=0x7 entropy=0.01 hits=[RWX,ROP] tag="RWX,ROP" stack=0x67b03dd1759769ae
...
[STATS] blocks tracked=7 suspicious=6 ring: produced=13 dropped=0 ...
```

每一行列出**一個可疑區塊**：位址、大小、權限、熵值、累積命中的偵測項、
呼叫堆疊雜湊。`hits=[RWX,ROP]` 代表同一區塊同時命中多個偵測器——
**多重命中的可信度遠高於單一命中**，處理順序上應優先。

`blocks tracked=N suspicious=M`：`M` 是需要人工看的比例；
`ring: produced= dropped=` 是全期統計，`dropped` 應為 0。

---

## 5. kernel 模組 `memory_tracker.ko`

### 5.1 載入與參數（需要 root）

```bash
sudo insmod build/memory_tracker.ko                 # 預設參數
sudo insmod build/memory_tracker.ko ring_size=32768 oversize_kb=512 trace_alloc=1
```

| 參數 | 預設 | 意義 |
|---|---|---|
| `ring_size` | `16384` | 每 CPU 追蹤 ring 格數（升到 2 的冪次） |
| `kblock_bits` | `16` | live-block table 容量 = 2^bits（clamp 10..22） |
| `oversize_kb` | `1024` | 分配 ≥ 此 KiB 數就發 `OVERSIZE` 告警；`0` 關閉 |
| `trace_alloc` | `0` | 每筆成功分配都輸出事件（很吵，只在需要完整軌跡時開） |
| `trace_free` | `0` | 每筆乾淨釋放都輸出事件 |
| `trace_unknown` | `0` | 輸出「釋放了我們沒看過的指標」事件（載入初期會海量誤報，故預設關） |

載入後可即時改寫可寫參數：

```bash
echo 1 | sudo tee /sys/module/memory_tracker/parameters/trace_alloc
```

卸載：`sudo rmmod memory_tracker`

### 5.2 debugfs 介面

```bash
D=/sys/kernel/debug/memory_tracker
cat  $D/stats        # 計數器、probe 掛載狀態表
cat  $D/events       # 已排空的追蹤事件（每次 open 拍快照，按時間排序）
echo 1 > $D/clear    # 丟棄未讀 backlog + 清空 live-block table（累計計數不動）
cat  $D/selftest     # 內建自我測試（6 項，最後一行 result: PASS (6/6)）
```

`events` 單行格式：

```
ts=<ns> type=<ALLOC|FREE|DOUBLE_FREE|WRONG_FREE|CACHE_MISMATCH|OVERSIZE|UNKNOWN_FREE|SELFTEST>
     pid=<pid> cpu=<n> ptr=0x... size=<n> caller=<symbol+off/size [module]> aux=0x... flags=0x...
```

`caller` 已在 **debugfs 讀取時**（非 IRQ context）用 `sprint_symbol` 解析成符號名，
可直接看出是哪個 kernel 函式發起的分配/釋放。

### 5.3 selftest 解讀

```
[1] kmalloc(128)               : OK ptr=0x...
[2] tracked as LIVE             : OK
[3] first release classified    : KBF_OK
[4] second release classified   : KBF_DOUBLE_FREE
[5] block restored to LIVE      : OK
[6] real kfree quarantined      : OK
result: PASS (6/6)
```

* `[4]` 是**分類器**的測試（直接呼叫分類函式兩次，**不真的對 SLUB 釋放兩次**，
  所以不會污染 allocator、不會造成系統損壞）；
* `[6]` 才是真的 `kfree()`，驗證 kprobe 鏈路通。
* 任何一項 `FAIL` 都代表對應的偵測能力在這台機器上失效。

### 5.4 kernel 偵測事件解讀

| 事件 | 意義 | 嚴重度 |
|---|---|---|
| `ALLOC` / `FREE` | 正常追蹤痕跡（受 `trace_alloc`/`trace_free` 開關控制） | 資訊 |
| `DOUBLE_FREE` | 同一指標被釋放第二次（slot 仍在 quarantine） | **告警** |
| `WRONG_FREE` | `kfree()` 釋放了 `kmem_cache_alloc()` 的區塊，或反過來 | **告警** |
| `CACHE_MISMATCH` | 用**另一個** cache 釋放（SLUB freelist 破壞的徵兆） | **告警** |
| `OVERSIZE` | 分配 ≥ `oversize_kb` | 告警（依需求判定） |
| `UNKNOWN_FREE` | 釋放了模組載入前就存在的指標（常見、**非惡意**） | 資訊 |

### 5.5 `stats` 重點欄位

```
[ring]         slots_per_cpu / rings / produced / dropped
[live-block]   capacity / live / quarantined
[probes]       registered_ok / registration_failed / kretprobe_instances_missed
[probe table]  每個 symbol 的 kprobe|kretprobe 與 OK|FAILED
```

* `registration_failed` 應為 **0**；非 0 時看 probe table 哪一行 `FAILED`
  （通常是符號被 blacklisted 或與 ftrace 衝突），代表**該類分配/釋放沒有被追蹤**；
* `kretprobe_instances_missed > 0` 表示 `maxactive` 不夠、有事件遺失；
* `dropped > 0` 表示 ring 滿了，請調大 `ring_size`；
* `quarantined` 是為了抓 double-free 而保留的已釋放 slot 數。

---

## 6. LD_PRELOAD 堆積守衛 `libtracker_preload.so`

```bash
# 任意 Linux 程式直接套用（不需要重編譯目標）
LD_PRELOAD=$PWD/build/libtracker_preload.so ./目標程式

# 另存 log、靜音 console、加大追蹤表
TRACKER_SHIM_LOG=/tmp/shim.log TRACKER_SHIM_QUIET=1 \
LD_PRELOAD=$PWD/build/libtracker_preload.so ./目標程式
```

| 環境變數 | 意義 |
|---|---|
| `TRACKER_SHIM_LOG` | 額外 append 到指定檔案 |
| `TRACKER_SHIM_QUIET` | `1` = 不印 console |
| `TRACKER_SHIM_TABLE` | 雜湊表格數（預設 65536） |

輸出範例：

```
[STATS] LD_PRELOAD heap guard active: table=65536 slots, redzone=16 bytes, ...
[OVERFLOW] *** redzone overrun (LD_PRELOAD shim): block 0x... size=16 offset=0 expected=0xF0 got=0x58 ...
[DOUBLE_FREE] *** double free (LD_PRELOAD shim): 0x... was already freed, block size=16 ***
[STATS] LD_PRELOAD heap guard stopped
```

* 啟動與結束各有一條 `[STATS]`，**若只有啟動沒有結束，代表目標程式非正常終止**。
* 它**不做 UAF 偵測**（釋放後 allocator 可能已重用，快照無從比對），
  UAF 由主追蹤器的 quarantine 快照負責；也不攔 `mmap/mprotect`（RWX 屬主追蹤器）。

---

## 7. 誤報、限制與注意事項

### 7.1 會誤報的場景

| 現象 | 原因 | 處理建議 |
|---|---|---|
| `[HIGH_ENTROPY]` 出現在壓縮檔/金鑰 | 真的高熵，但不是惡意 | 看 `stack` 雜湊是否為正規 I/O 路徑 |
| `[RET2LIBC]` 列出一堆危險函式 | 那只是「表面盤點」（DEBUG 級），不是告警 | 只看 `*** ... is SET ***` 與 `OUTSIDE` 兩種 |
| `[HOOK] malloc resolved into ...` | LD_PRELOAD / 自身映像替換了匯入表 | 自己跑追蹤器時屬**預期行為** |
| `[PERM_CHANGE]` 偶發一次 | dlopen / JIT 正常改權限 | 反覆翻轉或改成 RWX 才值得注意 |
| kernel `UNKNOWN_FREE` 海量出現 | 模組載入前已存在的分配我們沒看過 | 屬正常，預設不輸出事件只計數 |
| kernel `alloc_table_full` 上升 | live-block table 滿了 | 調大 `kblock_bits` |

### 7.2 硬性限制

1. **只能看到 3 秒錄製視窗內的事件**：視窗外發生的分配/釋放不會進本週期。
2. **ROP 只掃可執行區塊**：RW 區塊即使含 gadget 也不會命中（避免大量誤報）。
3. **ROP 需要 Capstone**：初始化失敗會留一條 `[ERROR]` 並停用該偵測器，其餘不影響。
4. **kernel 模組的追蹤範圍**：只掛 10 個 probe（`__kmalloc*` 家族、
   `kmem_cache_alloc*`、`kfree`、`kmem_cache_free`）；
   `vmalloc`/`kmem_cache_alloc_bulk` 等路徑不在覆蓋範圍，
   其釋放會落成 `UNKNOWN_FREE`（資訊級，非告警）。
5. **載入前的 kernel 分配不可知**，這是 `trace_unknown` 預設關閉的原因。
6. **`clear` 會清空 live-block table**：清過之後，之前釋放過的指標若再次被釋放，
   會重新變成 `UNKNOWN_FREE`，且 double-free 記憶被抹除。
7. **quarantine slot 會被回收**：table 滿時會犧牲最舊的隔離 slot，
   只會**削弱**偵測、不會產生假陽性。
8. **Windows 版本未在本機實測**：`tracker.exe` 與 `test_win.bat` 由使用者
   在 Windows 上自行執行（46 項斷言）。
9. **kernel 模組的載入測試需 root**：無權限時 `test_kmod.sh` 只做編譯層斷言，
   載入部分顯示 `SKIP`。

### 7.3 效能注意

* 每 20 秒只有 3 秒在錄製，其餘時間追蹤器幾乎零開銷。
* kernel 模組的 probe 在**每次** kmalloc/kfree 都會執行，
  熱記憶體配置的系統上會有可測量的開銷；正式監控建議
  `trace_alloc=0`（分配仍被追蹤以利分類，只是不印事件）。
* `ring` 或 `kblock` 調大會增加記憶體佔用：
  `ring_size × 64B × CPU數` 與 `2^kblock_bits × 40B`。

---

## 8. 測試與報告

| 指令 | 報告檔 | 斷言數 | 需要 |
|---|---|---|---|
| `make test` | `build/test_report.txt` + `build/shim_test_report.txt` | 46 + 7 | 無（localhost） |
| `make kmod-test` | `build/kmod_test_report.txt` | 15（+載入 9 項） | 編譯需 kernel headers；載入需 root |
| `tests/test_win.bat` | console | 46 | Windows |

報告結尾的 `OVERALL: PASS` 與 `FAIL=0` 是通過標準；
`SKIP` 只出現在權限不足的項目，不算失敗。

```bash
# 典型驗收流程
make test          # 使用者空間全部通過
make kmod-test     # 編譯層通過（有 root 才會載入實測）
make win           # 交叉編譯成功
make package       # 產出 dist/
```

---

## 9. 快速故障排查

| 症狀 | 可能原因 | 解法 |
|---|---|---|
| log 完全沒有事件 | 錄製視窗太短 / 沒有分配活動 | 加大 `--record`，或先跑 `--selftest` |
| `ring-dropped` 持續 > 0 | ring 太小 | `--ring 65536`（使用者）／`ring_size=`（kernel） |
| `[ERROR] ROP: capstone initialisation failed` | Capstone 無法初始化 | 確認連結到 `third_party/capstone`；其餘偵測器不受影響 |
| `registration_failed > 0`（kernel） | 符號被 blacklisted 或 ftrace 衝突 | 看 `stats` 的 probe table，該列 `FAILED` 即失去該覆蓋 |
| `events` 是空的 | ring 已被 `clear`，或 `trace_alloc/trace_free` 皆為 0 | 開啟對應開關或重新產生活動 |
| `insmod` 失敗 `Invalid module format` | 與目前 kernel 版本不符 | 用目前 kernel 的 headers 重新 `make kmod` |
| `test_kmod.sh` 出現 `SKIP` | 非 root 或 debugfs 未掛載 | `sudo make kmod-test`；確認 `/sys/kernel/debug` 存在 |
