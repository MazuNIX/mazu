# Build configuration

Mazu uses a [Kconfiglib](https://github.com/ulfalizer/Kconfiglib)-based
configuration system (the same Kconfig language used by the Linux
kernel). The configuration schema lives in `configs/Kconfig`.

```bash
make config             # interactive menuconfig TUI
make defconfig          # apply configs/defconfig (default config)
make defconfig DEFCONFIG=configs/rt_defconfig       # apply a named defconfig
make defconfig DEFCONFIG=configs/defconfig CONFIG_FRAGMENTS=configs/fragments/up.config
make savedefconfig      # save current .config back to configs/defconfig
make oldconfig          # update .config for new/changed Kconfig symbols
```

Kconfiglib is auto-cloned into `tools/kconfig/` on first use. The
generated `.config` file is included by Make, and `build/config.h` is
generated for C code. Disabled features contribute zero text and zero BSS
to the kernel image.

## Predefined configurations

| Defconfig | Description |
|-----------|-------------|
| `configs/defconfig` | Default hard-RT profile: SMP, EEVDF + EDF, mixed-criticality, latency tracing, TCP + SACK, UDP, mDNS, virtio-blk, semihosting (DHCP disabled; configure statically via `rootfs/config.txt`) |
| `configs/rt_defconfig` | Leaner RT validation profile: SMP, EEVDF, latency tracing, UDP + mDNS, TCP + SACK, semihosting (no EDF, no mixed-criticality, no virtio-blk) |

## Reusable configuration fragments

| Fragment | Description |
|----------|-------------|
| `configs/fragments/up.config` | Force uniprocessor mode for QEMU 8.2-based CI or local repros |
| `configs/fragments/ubsan.config` | Enable trap-mode UBSan on top of an existing defconfig |

## Key feature flags

All configurable via `make config`. The `Defconfig` column shows the
effective value after `make defconfig` (`configs/defconfig` overrides
several Kconfig defaults).

| Symbol | Defconfig | Description |
|--------|-----------|-------------|
| `CONFIG_NET_TCP` | y | TCP/IP stack with connection pool, Reno CC, RTT retransmission, sliding window |
| `CONFIG_TCP_SACK` | y | TCP selective acknowledgment (RFC 2018) |
| `CONFIG_WEBSOCKET` | y | WebSocket upgrade path (SHA-1, Base64, frame codec, PING/PONG/CLOSE) |
| `CONFIG_SCHED_PREEMPTIVE` | y | Mandatory timer-driven kernel preemption |
| `CONFIG_SCHED_EEVDF` | y | EEVDF fair scheduling within priority levels |
| `CONFIG_SCHED_DEADLINE` | y | EDF deadline scheduling with admission control |
| `CONFIG_MIXED_CRIT` | y | Mixed-criticality scheduling domains with budget enforcement |
| `CONFIG_SMP` | y | Symmetric multiprocessing (per-CPU run queues, load balancing) |
| `CONFIG_CPU_MAX` | 4 | Maximum number of supported harts |
| `CONFIG_NET_UDP` | y | UDP transport (required by mDNS / DHCP) |
| `CONFIG_NET_MDNS` | y | mDNS responder for `mazu.local` (RFC 6762, depends on `CONFIG_NET_UDP`) |
| `CONFIG_VIRTIO_BLK` | y | VirtIO block device driver |
| `CONFIG_RAMFS_WRITABLE` | y | Writable RAM filesystem |
| `CONFIG_SEMIHOSTING` | y | RISC-V semihosting for host communication and self-tests |
| `CONFIG_MEASURE_LATENCY` | y | Latency-tracing instrumentation |
| `CONFIG_EVENTLOG` | y | Per-CPU event log (binary, ringbuffer) |
| `CONFIG_STACK_PROTECTOR` | y | GCC `-fstack-protector-strong` (canary init from `rdtime` entropy) |
| `CONFIG_DHCP` | n | DHCPv4 boot-time client (Kconfig default is `y`; defconfig disables it) |
| `CONFIG_UBSAN` | n | Trap-mode UBSan (`-fsanitize=undefined -fsanitize-trap=all`) |
| `CONFIG_DEBUG_ENDPOINT` | n | `/debug` HTTP endpoint for runtime inspection |

A legacy configuration path via `config-riscv64.mk` is still supported for
backward compatibility when no `.config` file exists.

## Build/runtime knobs

- `DEBUG` controls kernel log verbosity:
  - `0`: warnings and errors
  - `1`: info
  - `2`: debug
  - `3`: verbose
- `RELEASE=1` enables optimized builds.

A practical default for development is `DEBUG=2` with `RELEASE` unset.

## Validation shortcuts

```bash
make check              # HTTP integration tests (SLIRP networking)
make check-selftest     # semihosting self-tests (requires CONFIG_SEMIHOSTING=y)
make check-smp          # SMP-focused checks (requires CONFIG_SMP=y)
./scripts/check.sh      # matrix-style checks across selected profiles
./scripts/check.sh --profile-matrix  # build + selftest defconfigs and CI overlays
```

## Runtime content model

- `rootfs/` is packed into the kernel image at build time by
  `scripts/archive.py`.
- `rootfs/config.txt` provides runtime network settings (used when DHCP
  is disabled or fails).
- `rootfs/web/` is the HTTP document root (static assets and web UI).
- `rootfs/hello.txt` is printed during boot.
