# ============================================================================
# Makefile - memory_tracker.ko (Linux kernel module)
# ----------------------------------------------------------------------------
# This file is consumed by the kernel build system (kbuild):
#
#     make            - build memory_tracker.ko against the running kernel
#     make clean      - remove kbuild artefacts
#     make M=$PWD     - same as "make" (explicit out-of-tree module dir)
#
# The top-level project Makefile simply forwards its `kmod` target here and
# copies the resulting .ko into build/ for packaging.
#
# KDIR can be overridden to build against a different set of headers:
#     make KDIR=/path/to/kernel/build
# ============================================================================

obj-m += memory_tracker.o

# Composite module: several translation units linked into one .ko.
# Keep this list in sync with the sources in this directory.
memory_tracker-y := tracker_kmod.o \
                    ring_kernel.o \
                    kblock.o \
                    probes.o \
                    debugfs_iface.o

# Extra warnings for our own code. The kernel build already passes -Wall;
# -Wno-unused-parameter is needed because probe handler signatures are fixed
# by the kretprobe ABI and not every parameter is meaningful in every handler.
ccflags-y := -Wall -Wextra -Wno-unused-parameter

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
