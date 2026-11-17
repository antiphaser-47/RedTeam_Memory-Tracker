# third_party — Capstone 反組譯引擎（交叉編譯產物）

本目錄存放**已編譯好的 Capstone 靜態庫與標頭**，供 `make win` 連結出
Windows x64 版的 `tracker.exe`。Linux 版的 `tracker_linux` 則使用系統安裝的
`libcapstone-dev`（apt），不使用這裡的產物——因為兩者是不同 ABI 的目標格式
（ELF vs PE）。

```
third_party/capstone/
├── include/capstone/   Capstone 4.0.2 公開標頭（capstone.h、x86.h ...）
└── lib/
    └── libcapstone.a   x86_64-w64-mingw32 靜態庫（約 1.6 MB，僅含 x86 支援）
```

## 為什麼需要自己編

專案在 `src/core/detector_rop.c` 用 Capstone 做 **ROP gadget 的精篩**
（byte-pattern 初篩 → 反組譯驗證）。Linux 有發行版打包的 capstone，
Windows 這邊 MinGW 沒有現成、且需與 `-static` 的連結策略一致，
所以從官方 sdist 交叉編譯一份 **x86-only** 的靜態庫。

## 重現步驟（Ubuntu / Debian，需要 `gcc-mingw-w64-x86-64`）

```bash
# 1. 取得原始碼（PyPI 上的 capstone sdist 與 GitHub release 內容一致）
pip download capstone==4.0.2 --no-binary :all: --no-deps -d /tmp/cs
tar xf /tmp/cs/capstone-4.0.2.tar.gz -C /tmp/cs

# 2. 交叉編譯（Capstone 4.x 的 makefile）
cd /tmp/cs/capstone-4.0.2
make clean
make CAPSTONE_ARCHS="x86" \
     CC=x86_64-w64-mingw32-gcc \
     AR=x86_64-w64-mingw32-ar \
     RANLIB=x86_64-w64-mingw32-ranlib \
     -j"$(nproc)"
#    產物: libcapstone.a（PE/COFF 格式，僅 x86 解碼器）

# 3. 安裝到專案的 third_party
cp libcapstone.a  <專案>/third_party/capstone/lib/
cp include/capstone/*.h  <專案>/third_party/capstone/include/capstone/
```

驗證產物格式：

```bash
file third_party/capstone/lib/libcapstone.a
# 應顯示 current ar archive，成員為 PE32+ x86-64 relocatable
```

## Linux 端的對應作法

```bash
sudo apt install libcapstone-dev     # 提供 /usr/lib/.../libcapstone.so 與標頭
make user                            # 連結系統的 capstone
```

Makefile 中的 `CAPSTONE_LIBS` 會依目標平台選擇：
`make win` 走 `-Ithird_party/capstone/include -Lthird_party/capstone/lib -lcapstone`，
`make user` 走系統函式庫。

## 授權

Capstone 依 **BSD 3-Clause** 授權，與本專案的使用方式相容；
原始碼與授權全文見上游 <https://github.com/capstone-engine/capstone>。
