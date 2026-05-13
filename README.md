# The Mazu Operating System

`mazu` is a bare-metal RISC-V 64-bit hard RTOS that combines Linux kernel
discipline with Plan 9 philosophy in a system small enough to read end to
end. SMP correctness, hard real-time scheduling, and kernel-integrated
networking are not bolted on after the fact; they shape every data
structure and code path from the start.

Unlike RTOSes that treat networking as an optional middleware layer and
SMP as a bolt-on configuration flag, Mazu takes the opposite position: a
connected embedded system needs bounded-latency scheduling, per-CPU
execution paths, and a TCP/IP stack that respects both, all in the same
address space, all under the same lock discipline. The kernel serves REST
APIs and runs a web-based shell as ordinary preemptible tasks alongside
deadline-scheduled control work.

Two design lineages run through the codebase:
- From Linux: subsystem modularity (initcall registration, irqchip
  vtables, IRQ descriptor tables, waitqueues, lockdep), synchronization
  primitives (priority-inheritance mutexes, futexes with PI and requeue,
  counting semaphores with direct handover), buddy allocator, per-CPU
  data via the `gp` register, and the convention that every subsystem is
  SMP-safe or explicitly documented otherwise.
- From Plan 9: the "everything is a file" control plane. Synthetic
  filesystems (`/dev`, `/proc`, `/net`) expose hardware, process state,
  and network tables as readable files. No `ioctl`, no sysfs, no procfs
  special-case parsers. System observability comes from
  `cat /net/tcp/stats`, not a dedicated monitoring daemon.

What Mazu does not import from either lineage is equally deliberate: no
loadable modules, no virtual memory isolation between tasks, no VFS page
cache, no socket API. The kernel runs all tasks in a single shared page
table (identity-mapped kernel space, shared user mappings at fixed VAs)
with VMA-based access control, and the networking API is a direct
function interface rather than a Berkeley sockets layer. Disk-backed SFS
has its own block buffer cache (`kernel/fs/bcache.c`); the synthetic and
RAM filesystems are uncached because their data is either memory-resident
or generated on demand.

For the detailed rationale behind these choices, see
[docs/design.md](docs/design.md).

## PSE51 framing

Mazu implements a bounded PSE51-oriented userspace core with deliberate
filesystem and multi-process supersets. PSE51 itself is a single-process,
threaded, no-filesystem profile; Mazu ships a real filesystem,
`SYS_SPAWN` / `SYS_WAIT`, and multiple PIDs by design, so the honest
top-level framing of the user-visible environment is closer to PSE52
(Realtime Controller System Profile). The kernel-level primitives that
back PSE51-facing syscalls (PI mutexes, condvars, semaphores, futexes,
barriers, rwlocks, message queues, POSIX timers) are already in place.
Per-syscall conformance status, including which entries use a
Mazu-specific ABI shape rather than the exact POSIX shape, is tracked in
[docs/pse51-matrix.md](docs/pse51-matrix.md).

## Core capabilities

- Hard-RT scheduling: mandatory kernel preemption, SMP per-CPU run
  queues, EEVDF fairness, EDF deadline scheduling with admission
  control, mixed-criticality domains, load balancing, scheduling domains
  with budget enforcement.
- SMP by design: per-hart state via `gp` register, per-CPU run queues
  and merged deadline management, lockdep lock-ordering enforcement,
  cache-line-aligned per-CPU structures.
- Kernel-integrated networking: IPv4, TCP (Reno CC, SACK, RTT
  estimation, connection pooling, per-IP flood limits), optional
  UDP/DHCP/mDNS, outbound client connections, HTTP/1.1 server with REST
  endpoints, WebSocket, and SSE; all running as preemptible scheduler
  tasks.
- Plan 9-style VFS: synthetic `/dev`, `/proc`, `/net` alongside a RAM
  filesystem with optional writable and virtio-blk paths.
- Linux-grade synchronization: PI mutexes with direct handover,
  condition variables, counting semaphores, futexes
  (WAIT / WAKE / CMP_REQUEUE / LOCK_PI / UNLOCK_PI).
- Type-driven safety: length-prefixed fat strings (never
  null-terminated), macro-generated result types,
  read-only/read-write/appendable buffer types encoding mutability in
  the type system.
- Memory: buddy allocator for pages, pool allocators for fixed-size
  objects, arena allocators for request-scoped temporaries, pluggable
  allocator vtable.
- Kernel-user isolation: W^X, VMA-based user-pointer containment
  validation, per-process syscall allow-list, kernel-stack guard pages,
  stack-protector canaries.
- Debug and verification: lockdep, scheduler invariant checks on every
  context switch, callout lateness histograms, self-test framework,
  UBSan trap mode, static analysis via clang.
- QEMU `virt` machine: virtio-mmio devices, PLIC, OpenSBI, Sv39 paging
  (identity-mapped, 2 MiB superpages with on-demand shattering).

## Quick start

Primary development target is QEMU on Linux with standard tooling
(`make`, `python3`, RISC-V cross toolchain, QEMU).

SLIRP networking (local host access):

```bash
make defconfig          # generate .config from configs/defconfig
DEBUG=2 make run        # build and launch in QEMU (http://localhost:8080)
```

TAP networking (guest at `192.168.100.2`, Linux + iptables required):

```bash
export IF=eth0          # outward-facing host interface
./scripts/setup_vm_network.sh
TAP=1 make run
```

Validation:

```bash
make check              # HTTP integration tests (SLIRP)
make check-selftest     # semihosting self-tests (CONFIG_SEMIHOSTING=y)
make check-smp          # SMP-focused checks (CONFIG_SMP=y)
```

For Kconfig usage, defconfigs, fragments, and feature flags, see
[docs/build.md](docs/build.md).

## HTTP and REST API surface

The web server (`user/net/web.c`) provides both static file serving and
dynamic REST API endpoints. Current API surface:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Kernel stats (tasks, IRQs, memory, scheduler, callout, security) as JSON |
| `/api/tcp` | GET | TCP connection table (including cwnd/ssthresh per connection) as JSON |
| `/api/arp` | GET | ARP table as JSON |
| `/api/klog` | GET | Kernel log ring buffer as JSON |
| `/api/fs?path=X` | GET | Directory listing as JSON |
| `/api/fs/read?path=X` | GET | File content as text/plain |
| `/api/shell/in` | GET/POST | Web terminal: create session / submit command |
| `/api/shell/out` | GET | Web terminal: read output (polling) |
| `/api/sse/test` | GET | SSE test endpoint (chunked transfer encoding) |

WebSocket upgrade is supported for real-time communication (e.g.,
terminal streaming). Additional MIME types and API endpoints can be
added in `user/net/web.c`.

## Documentation

- [docs/design.md](docs/design.md): design philosophy, Linux/Plan 9
  lineage, SMP as a structural property, real-time and networking
  co-design, programming style.
- [docs/internals.md](docs/internals.md): boot, tasks, networking, TCP
  state machine and allocators, RAM fs.
- [docs/build.md](docs/build.md): Kconfig system, defconfigs,
  fragments, feature flags, build/runtime knobs, validation
  shortcuts.
- [docs/security.md](docs/security.md): threat model, deployment
  constraints, syscall authorization, memory safety hardenings.
- [docs/debugging.md](docs/debugging.md): GDB workflow, lockdep,
  scheduler invariants, callout telemetry, UBSan trap mode, self-test
  framework, semihosting console.
- [docs/pse51-matrix.md](docs/pse51-matrix.md): per-syscall PSE51
  conformance status.

## License

`mazu` is available under a permissive
[MIT](https://opensource.org/license/mit)-style license. Use of this
source code is governed by a MIT license that can be found in the
[LICENSE](LICENSE) file.
