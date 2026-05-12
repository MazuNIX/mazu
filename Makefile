# Mazu Kernel — RISC-V 64-bit
#
# Quick start:
#   make defconfig          # generate .config and build/config.h
#   make                    # build kernel ELF
#   DEBUG=2 make run        # build and launch in QEMU
#   RUN_PORT=8081 make run  # launch on an alternate HTTP port
#
# Configuration:
#   make config             # interactive menuconfig TUI
#   make defconfig          # apply configs/defconfig
#   make savedefconfig      # save minimal .config to configs/defconfig

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.PHONY: all clean distclean run check check-selftest check-smp indent
.PHONY: config defconfig oldconfig savedefconfig analyze install-hooks test-host

DEBUG      ?= 0
ARCH       ?= riscv64
BUILD_DIR  := build
KERNEL_ELF := $(BUILD_DIR)/kernel.elf
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
HEADER_CONFIG := $(BUILD_DIR)/config.h

# Verbosity
ifeq ($(V),1)
Q :=
else
Q := @
endif

# Build framework
include mk/toolchain.mk
include mk/kconfig.mk

# Configuration (via Kconfiglib)
ifeq ($(wildcard .config),)
# Allow config targets to run without .config; all others require it.
ifeq ($(filter config defconfig oldconfig clean distclean indent,$(MAKECMDGOALS)),)
$(info No .config found; run 'make defconfig' first.)
$(error .config required — see configs/ for available defconfigs)
endif
else
-include .config
endif

# Config header generation
$(HEADER_CONFIG): .config | $(BUILD_DIR)
	$(Q)KCONFIG_CONFIG=.config python3 $(KCONFIG_DIR)/genconfig.py \
		--header-path $@ configs/Kconfig 2>/dev/null || \
		./scripts/make_config.sh -f header -o $@ .config
	$(Q)echo "" >> $@
	$(Q)echo "#define PAGE_SIZE CONFIG_PAGE_SIZE" >> $@
	$(Q)echo "#define GIT_COMMIT \"$(GIT_COMMIT)\"" >> $@

# Source file lists

# Core (always compiled)
kernel_files-y := kernel/init/main.c kernel/printk.c kernel/rtcfg.c kernel/irq/irqdesc.c
kernel_files-y += kernel/init/hooks.c kernel/init/initgraph.c

# Memory
kernel_files-y += kernel/mm/buddy.c kernel/mm/kvalloc.c

# Filesystem
kernel_files-y += kernel/fs/ramfs.c kernel/fs/archive.c kernel/fs/vfs.c
kernel_files-y += kernel/fs/devfs.c kernel/fs/procfs.c kernel/fs/netfs.c
kernel_files-$(CONFIG_VIRTIO_BLK) += kernel/fs/bcache.c kernel/fs/sfs.c

# Scheduler
kernel_files-y += kernel/sched/core.c kernel/sched/waitqueue.c kernel/sched/kthread.c kernel/kres.c
kernel_files-$(CONFIG_SCHED_DEADLINE) += kernel/sched/deadline.c
kernel_files-$(CONFIG_MIXED_CRIT) += kernel/sched/mixed_crit.c

# Callout engine (one-shot timers for sleep, preemption, idle)
kernel_files-y += kernel/timer/callout.c kernel/timer/posix_timer.c

# Synchronization primitives (futex, PI mutex, condvar, semaphore)
kernel_files-y += kernel/sync/futex.c kernel/sync/mutex.c \
    kernel/sync/condvar.c kernel/sync/semaphore.c \
    kernel/sync/sync_handle.c kernel/sync/barrier.c \
    kernel/sync/rwlock.c
kernel_files-y += kernel/ipc/mqueue.c

# Kernel log ring buffer
kernel_files-y += kernel/klog.c

# Structured event log (KTRACE) -- selftest host file
kernel_files-y += kernel/eventlog.c

# User-space process support
kernel_files-y += kernel/proc/uaccess.c kernel/proc/proc.c \
    kernel/proc/syscall.c kernel/proc/loader.c kernel/proc/spawn.c \
    kernel/proc/cap.c \
    kernel/proc/pipe.c kernel/proc/signal.c

# TCP/IP stack
kernel_files-$(CONFIG_NET_TCP) += \
    kernel/net/tcp.c kernel/net/ip.c \
    kernel/net/arp.c kernel/net/icmp.c kernel/net/netdev.c kernel/net/send_buf.c

# User-facing services (require TCP)
user_files-$(CONFIG_NET_TCP) += user/net/web.c user/shell.c

# UDP listener table (generic dispatch + send path)
kernel_files-$(CONFIG_NET_UDP) += kernel/net/udp.c
kernel_files-$(CONFIG_NET_UDP) += kernel/net/dns.c

# DHCP (requires UDP)
kernel_files-$(CONFIG_DHCP) += kernel/net/dhcp.c

# mDNS (requires UDP)
kernel_files-$(CONFIG_NET_MDNS) += kernel/net/mdns.c

# Library (always compiled)
lib_files-y := lib/string.c lib/json.c lib/ip_addr.c lib/builtins.c
lib_files-$(CONFIG_STACK_PROTECTOR) += lib/stack_chk.c

# WebSocket support (requires TCP)
lib_files-$(CONFIG_WEBSOCKET) += lib/sha1.c lib/base64.c

# Drivers
drivers_files-y := drivers/serial/uart.c
drivers_files-$(CONFIG_NET_TCP) += drivers/net/virtio_mmio.c
drivers_files-$(CONFIG_VIRTIO_BLK) += drivers/block/virtio_blk.c

# Architecture ($(ARCH))
arch_files-y := \
    arch/$(ARCH)/entry.c arch/$(ARCH)/trap.c \
    arch/$(ARCH)/paging.c arch/$(ARCH)/time.c \
    arch/$(ARCH)/arch.c \
    arch/$(ARCH)/sbi.c \
    arch/$(ARCH)/sched.c \
    arch/$(ARCH)/fdt.c
arch_files-$(CONFIG_SMP) += arch/$(ARCH)/smp_boot.c
arch_files-$(CONFIG_SEMIHOSTING) += arch/$(ARCH)/semihost.c

# Self-test framework (requires semihosting for exit code)
lib_files-$(CONFIG_SEMIHOSTING) += lib/selftest.c

# --- Object files -------------------------------------------------------------

SRCS := $(kernel_files-y) $(lib_files-y) $(drivers_files-y) $(arch_files-y) $(user_files-y)
OBJS := $(patsubst %, $(BUILD_DIR)/%.o, $(SRCS))
DEPS := $(patsubst %.c.o, %.c.d, $(filter %.c.o, $(OBJS)))

ROOTFS_DIR     := rootfs/
ROOTFS_OBJ     := $(BUILD_DIR)/rootfs.o
ROOTFS_ARCHIVE := $(BUILD_DIR)/rootfs.img

# --- Build rules --------------------------------------------------------------

all: $(KERNEL_ELF)
	$(Q)if [ -d .git/hooks ] && \
	    { [ ! -L .git/hooks/pre-commit ] || \
	      [ ! -L .git/hooks/commit-msg ] || \
	      [ ! -L .git/hooks/prepare-commit-msg ]; }; then \
	    $(MAKE) --no-print-directory install-hooks; \
	fi

$(KERNEL_ELF): $(OBJS) $(ROOTFS_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(LD) $(ARCH_LDFLAGS) -o $@ $^ $(LIBGCC)

-include $(DEPS)

$(BUILD_DIR)/%.c.o: %.c $(HEADER_CONFIG) | $(BUILD_DIR)
	$(Q)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CPPFLAGS) -include $(HEADER_CONFIG) -D__DEBUG__=$(DEBUG) \
		-D__BASENAME__=\"$(notdir $<)\" $(CFLAGS) -c $< -o $@

# --- User-space programs ------------------------------------------------------

USER_HELLO_SRC := user/hello.S
USER_HELLO_OBJ := $(BUILD_DIR)/user/hello.o
USER_HELLO_ELF := $(BUILD_DIR)/user/hello.elf
USER_HELLO_BIN := rootfs/bin/hello

$(USER_HELLO_OBJ): $(USER_HELLO_SRC) $(HEADER_CONFIG) | $(BUILD_DIR)
	$(Q)mkdir -p $(dir $@)
	@echo "  AS      $<"
	$(Q)$(CC) $(CPPFLAGS) -I$(dir $(HEADER_CONFIG)) $(ARCH_CFLAGS) -nostdlib -c $< -o $@

$(USER_HELLO_ELF): $(USER_HELLO_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(LD) -m elf64lriscv --no-relax -Ttext=0x10000 -o $@ $<

$(USER_HELLO_BIN): $(USER_HELLO_ELF)
	$(Q)mkdir -p $(dir $@)
	@echo "  OBJCOPY $@"
	$(Q)$(OBJCOPY) -O binary $< $@

USER_BINS := $(USER_HELLO_BIN)

# --- Rootfs archive -----------------------------------------------------------

$(ROOTFS_OBJ): $(ROOTFS_ARCHIVE) | $(BUILD_DIR)
	@echo "  OBJCOPY $@"
	$(Q)$(OBJCOPY) $< -I binary -O elf64-littleriscv -B riscv \
		--rename-section .data=.rootfs_archive,alloc,load,readonly,data,contents $@

ROOTFS_FILES := $(shell find $(ROOTFS_DIR) -type f 2>/dev/null)

$(ROOTFS_ARCHIVE): $(ROOTFS_FILES) $(USER_BINS) | $(BUILD_DIR)
	@echo "  ARCHIVE $@"
	$(Q)./scripts/archive.py enc $(ROOTFS_DIR) $@

$(BUILD_DIR):
	$(Q)mkdir -p $@

# --- QEMU configuration ------------------------------------------------------

QEMU_BASE := qemu-system-riscv64 -machine virt -cpu rv64 -m 1G \
	     -device virtio-net-device,netdev=net0

RUN_PORT       ?= 8080
QEMU_SLIRP_NET := -netdev user,id=net0,net=192.168.100.0/24,host=192.168.100.1,hostfwd=tcp:127.0.0.1:$(RUN_PORT)-192.168.100.2:80
QEMU_TAP_NET   := -netdev tap,id=net0,ifname=vm0,script=no,downscript=no
QEMU_PCAP      := -object filter-dump,id=dump0,netdev=net0,file=.packets.pcap
CHECK_PORT     ?= 18080
CHECK_QEMU_SLIRP_NET := -netdev user,id=net0,net=192.168.100.0/24,host=192.168.100.1,hostfwd=tcp:127.0.0.1:$(CHECK_PORT)-192.168.100.2:80
CHECK_WEB_URL  := http://localhost:$(CHECK_PORT)

ifneq ($(TAP),)
QEMU_NETDEV     := $(QEMU_TAP_NET) $(QEMU_PCAP)
QEMU_NET_MODE   := tap
QEMU_WEB_URL    := http://192.168.100.2
else
QEMU_NETDEV     := $(QEMU_SLIRP_NET) $(QEMU_PCAP)
QEMU_NET_MODE   := slirp
QEMU_WEB_URL    := http://localhost:$(RUN_PORT)
endif

ifneq ($(GDB),)
QEMU_GDB_FLAGS := -s -S
endif

ifneq ($(filter y,$(CONFIG_SEMIHOSTING)),)
QEMU_SEMI := -semihosting-config enable=on,target=native
else
QEMU_SEMI :=
endif

ifneq ($(filter y,$(CONFIG_SMP)),)
QEMU_SMP := -smp $(or $(CONFIG_CPU_MAX),4)
else
QEMU_SMP :=
endif

ifneq ($(filter y,$(CONFIG_VIRTIO_BLK)),)
$(BUILD_DIR)/disk.img: | $(BUILD_DIR)
	@echo "  DISKIMG $@"
	$(Q)dd if=/dev/zero of=$@ bs=1M count=4 2>/dev/null
QEMU_BLK := -drive file=$(BUILD_DIR)/disk.img,format=raw,if=none,id=blk0 \
	     -device virtio-blk-device,drive=blk0
else
QEMU_BLK :=
endif

# --- Run (QEMU) ---------------------------------------------------------------

CHECK_DEPS := $(KERNEL_ELF) $(if $(filter y,$(CONFIG_VIRTIO_BLK)),$(BUILD_DIR)/disk.img)

run: $(CHECK_DEPS)
	@rm -f .packets.pcap
	@echo "Mazu kernel on QEMU ($(QEMU_NET_MODE) networking)"
	@echo "Web UI: $(QEMU_WEB_URL)"
	@echo -----------------
	@if [ "$(QEMU_NET_MODE)" = "slirp" ]; then \
		if curl -s -o /dev/null --max-time 1 $(QEMU_WEB_URL)/ 2>/dev/null; then \
			echo "Port $(RUN_PORT) is already serving HTTP."; \
			echo "Use RUN_PORT=<port> make run to pick another port."; \
			exit 1; \
		fi; \
	fi
	@$(QEMU_BASE) -kernel $< \
		$(QEMU_NETDEV) \
		$(QEMU_SEMI) \
		$(QEMU_SMP) \
		$(QEMU_BLK) \
		-serial stdio -display none -no-reboot \
		$(QEMU_GDB_FLAGS)

# --- Integration test ---------------------------------------------------------

CHECK_PID     := $(BUILD_DIR)/check_qemu.pid
CHECK_LOG     := $(BUILD_DIR)/check_serial.log
CHECK_TIMEOUT ?= 30
CHECK_SELFTEST_TIMEOUT ?= 120
CHECK_SELFTEST_PID := $(BUILD_DIR)/check_selftest_qemu.pid
CHECK_SELFTEST_LOG := $(BUILD_DIR)/check_selftest_serial.log

check: $(CHECK_DEPS)
	@echo "=== Mazu self-check ==="
ifeq ($(filter y,$(CONFIG_SEMIHOSTING)),y)
	@echo "-- semihost selftests --"
	@$(MAKE) --no-print-directory check-selftest
else
	@echo "-- semihost selftests skipped (CONFIG_SEMIHOSTING disabled) --"
endif
	@echo "-- pre-boot checks --"
	@python3 ./scripts/archive.py test $(ROOTFS_DIR)
	@echo "-- booting kernel (SLIRP) --"
	@if command -v lsof >/dev/null 2>&1; then \
		if lsof -i :$(CHECK_PORT) -sTCP:LISTEN -t >/dev/null 2>&1; then \
			echo "FAIL: port $(CHECK_PORT) already in use (stale QEMU or another process)"; \
			echo "Kill it or use CHECK_PORT=<port> make check"; \
			exit 1; \
		fi; \
	fi
	@rm -f "$(CHECK_PID)" "$(CHECK_LOG)"; \
	$(QEMU_BASE) -kernel $(KERNEL_ELF) \
		$(CHECK_QEMU_SLIRP_NET) \
		$(QEMU_SEMI) \
		$(QEMU_SMP) \
		$(QEMU_BLK) \
		-serial file:$(CHECK_LOG) -monitor none -display none -no-reboot \
		-pidfile $(CHECK_PID) 2>/dev/null & \
	BGPID=$$!; \
	cleanup() { \
	  kill "$$BGPID" 2>/dev/null; \
	  sleep 0.5; \
	  kill -0 "$$BGPID" 2>/dev/null && kill -9 "$$BGPID" 2>/dev/null; \
	  wait "$$BGPID" 2>/dev/null; \
	  rm -f "$(CHECK_PID)"; \
	}; \
	trap cleanup EXIT INT TERM; \
	 echo "Waiting for kernel (timeout $(CHECK_TIMEOUT)s)..."; \
	 READY=0; \
	 for i in $$(seq 1 $(CHECK_TIMEOUT)); do \
	   if kill -0 $$BGPID 2>/dev/null; then \
	     printf "  [%02d/%02d] kernel not ready yet (qemu pid=%s)\n" "$$i" "$(CHECK_TIMEOUT)" "$$BGPID"; \
	   else \
	     printf "  [%02d/%02d] qemu is not running\n" "$$i" "$(CHECK_TIMEOUT)"; \
	   fi; \
	   if curl -s -o /dev/null --max-time 1 $(CHECK_WEB_URL)/ 2>/dev/null; then \
	     READY=1; break; \
	   fi; \
	   sleep 1; \
	 done; \
	 if [ "$$READY" != "1" ]; then \
	   echo "FAIL: kernel did not become ready in $(CHECK_TIMEOUT)s"; \
	   if [ -f $(CHECK_LOG) ]; then \
	     echo "Hint: see $(CHECK_LOG) (last 40 lines):"; \
	     tail -n 40 $(CHECK_LOG); \
	   else \
	     echo "Hint: no serial log found at $(CHECK_LOG)"; \
	   fi; \
	   exit 1; \
	 fi; \
	 if ! kill -0 $$BGPID 2>/dev/null; then \
	   echo "FAIL: QEMU is not running (port $(CHECK_PORT) served by another process?)"; \
	   exit 1; \
	 fi; \
	 echo "Kernel ready (pid $$BGPID)"; \
	 if [ "$(filter y,$(CONFIG_EVENTLOG))" = "y" ]; then \
	   echo "-- KTRACE replay verification (early snapshot) --"; \
	   curl -s --max-time 5 $(CHECK_WEB_URL)/api/klog 2>/dev/null | \
	     python3 ./scripts/check_eventv1.py -q || \
	     echo "  (KTRACE replay: warnings above are non-fatal)"; \
	 fi; \
	 echo "-- running integration tests --"; \
	 bash ./scripts/check.sh $(CHECK_WEB_URL); \
	 exit $$?

# --- Self-test (semihosting) --------------------------------------------------

check-selftest: $(CHECK_DEPS)
ifeq ($(filter y,$(CONFIG_SEMIHOSTING)),)
	@echo "ERROR: CONFIG_SEMIHOSTING is not enabled (set CONFIG_SEMIHOSTING=y in .config)"; exit 1
else
	@echo "=== Mazu self-test (semihosting) ==="
	@rm -f "$(CHECK_SELFTEST_PID)" "$(CHECK_SELFTEST_LOG)"; \
	$(QEMU_BASE) -kernel $(KERNEL_ELF) \
		-semihosting-config enable=on,target=native \
		$(QEMU_SMP) \
		$(QEMU_BLK) \
		-append "selftest" \
		-serial file:$(CHECK_SELFTEST_LOG) -display none -no-reboot \
		-netdev user,id=net0 \
		-pidfile $(CHECK_SELFTEST_PID) 2>/dev/null & \
	BGPID=$$!; \
	cleanup() { \
	  kill "$$BGPID" 2>/dev/null; \
	  sleep 0.5; \
	  kill -0 "$$BGPID" 2>/dev/null && kill -9 "$$BGPID" 2>/dev/null; \
	  wait "$$BGPID" 2>/dev/null; \
	  rm -f "$(CHECK_SELFTEST_PID)"; \
	}; \
	trap cleanup EXIT INT TERM; \
	printf "  [001/%03d] starting selftests\n" "$(CHECK_SELFTEST_TIMEOUT)"; \
	PREV_LAST=""; STALL_COUNT=0; STALL_SHOWN=""; \
	for i in $$(seq 2 $(CHECK_SELFTEST_TIMEOUT)); do \
	  sleep 1; \
	  if kill -0 "$$BGPID" 2>/dev/null; then \
	    LAST=$$(tail -n 1 "$(CHECK_SELFTEST_LOG)" 2>/dev/null | tr -d '\r'); \
	    if [ -n "$$LAST" ]; then \
	      if [ "$$LAST" = "$$PREV_LAST" ]; then \
	        STALL_COUNT=$$((STALL_COUNT + 1)); \
	        if [ "$$STALL_COUNT" -ge 5 ] && [ -z "$$STALL_SHOWN" ]; then \
	          printf "  [%03d/%03d] stalled on: %s (waiting...)\n" "$$i" "$(CHECK_SELFTEST_TIMEOUT)" "$$LAST"; \
	          STALL_SHOWN=1; \
	        fi; \
	      else \
	        printf "  [%03d/%03d] selftests running: %s\n" "$$i" "$(CHECK_SELFTEST_TIMEOUT)" "$$LAST"; \
	        PREV_LAST="$$LAST"; STALL_COUNT=0; STALL_SHOWN=""; \
	      fi; \
	    fi; \
	  else \
	    break; \
	  fi; \
	done; \
	if kill -0 "$$BGPID" 2>/dev/null; then \
	  echo "FAIL (selftests timed out after $(CHECK_SELFTEST_TIMEOUT)s; override with CHECK_SELFTEST_TIMEOUT=<sec>)"; \
	  echo "Hint: see $(CHECK_SELFTEST_LOG) (last 60 lines):"; \
	  tail -n 60 "$(CHECK_SELFTEST_LOG)" 2>/dev/null || true; \
	  exit 1; \
	fi; \
	wait "$$BGPID" 2>/dev/null; \
	RC=$$?; \
	if [ "$$RC" -eq 0 ]; then \
	  echo "PASS"; \
	else \
	  echo "FAIL (exit $$RC)"; \
	  echo "Hint: see $(CHECK_SELFTEST_LOG) (last 60 lines):"; \
	  tail -n 60 "$(CHECK_SELFTEST_LOG)" 2>/dev/null || true; \
	  exit 1; \
	fi
endif

# --- SMP integration test -----------------------------------------------------

check-smp: $(CHECK_DEPS)
ifeq ($(filter y,$(CONFIG_SMP)),)
	@echo "ERROR: CONFIG_SMP is not enabled"; exit 1
else
	@echo "=== Mazu SMP check ($(or $(CONFIG_CPU_MAX),4) harts) ==="
	@$(MAKE) --no-print-directory check
endif

# --- Host-native unit tests (no QEMU) -----------------------------------------

test-host:
	@$(MAKE) --no-print-directory -C tests/host

# --- compile_commands.json (for clang-tidy, cppcheck, IDEs) -------------------

COMPDB := compile_commands.json

$(COMPDB): $(HEADER_CONFIG) .config Makefile mk/toolchain.mk
	$(Q)python3 scripts/gen_compdb.py \
		--cc "$(CC)" \
		--cppflags "$(CPPFLAGS)" \
		--cflags "$(CFLAGS)" \
		--config-header "$(HEADER_CONFIG)" \
		--debug "$(DEBUG)" \
		--build-dir "$(BUILD_DIR)" \
		--root "$(CURDIR)" \
		-o $@ \
		$(SRCS)
	@echo "  COMPDB  $@ ($(words $(SRCS)) entries)"

analyze: $(HEADER_CONFIG) $(COMPDB)
	@bash ./scripts/analyze.sh

# --- Code formatting ----------------------------------------------------------

INDENT_C   := $(shell find arch drivers include kernel lib user tests -name '*.c' -o -name '*.h')
INDENT_PY  := $(shell find scripts -maxdepth 1 -name '*.py')
INDENT_SH  := $(shell find scripts -maxdepth 1 -name '*.sh')
INDENT_LD  := $(shell find arch -name '*.ld')

indent:
	@echo "  Formatting ..."
	$(Q)clang-format -i $(INDENT_C)
	$(Q)black -q $(INDENT_PY)
	$(Q)shfmt -i 4 -ci -w $(INDENT_SH)
	$(Q)python3 scripts/indent_ld.py $(INDENT_LD)

# --- Git hooks ----------------------------------------------------------------

install-hooks:
	$(Q)for hook in scripts/*.hook; do \
		name=$$(basename "$$hook" .hook); \
		if [ ! -L .git/hooks/"$$name" ]; then \
			ln -sf ../../"$$hook" .git/hooks/"$$name"; \
			echo "  HOOK    $$name"; \
		fi; \
	done

# --- Clean --------------------------------------------------------------------

clean:
	$(Q)$(RM) -r $(BUILD_DIR)
	$(Q)$(RM) -f ./*.plist
	@echo Deleted artifacts

distclean: clean
	$(Q)$(RM) -r $(KCONFIG_DIR) .config
	@echo Deleted config and tools
