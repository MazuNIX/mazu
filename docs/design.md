# Design philosophy

Mazu sits at an intersection that few systems occupy. Linux is the gold
standard for SMP correctness and subsystem modularity but carries decades of
generality that a hard-RT embedded kernel cannot afford. Plan 9 solved the
observability problem elegantly (expose system state as files, not ioctls)
but never targeted real-time or bare-metal embedded systems. Mazu takes the
structural discipline of one and the operational philosophy of the other, and
leaves behind the parts that conflict with bounded latency and small code
size.

## Lineage: what Mazu takes from Linux and Plan 9

From Linux, Mazu borrows the patterns that keep a concurrent kernel honest:
level-ordered init hooks (`DEFINE_INIT_HOOK` with `INIT_LEVEL_CORE` /
`INIT_LEVEL_SUBSYS` levels, plus a DAG-based initgraph for dependency
ordering), irqchip vtables that decouple trap dispatch from PLIC-specific
MMIO, IRQ descriptor tables with `request_irq()` / `free_irq()` registration,
lockdep-style lock-ordering enforcement via per-CPU `held_locks` bitmasks,
waitqueue-based blocking with timeout callouts, and per-CPU state accessed
through the `gp` register so that hot-path scheduler and timer code never
touches a global lock. The synchronization primitives (PI mutexes with
direct handover, condition variables, semaphores with FIFO direct-handover,
futexes with CMP_REQUEUE and PI) are not simplified versions of their Linux
counterparts; they enforce the same invariants, just without the
backward-compatibility layers.

From Plan 9, Mazu borrows the idea that system state belongs in the
filesystem namespace. Three synthetic filesystems (`/dev` with null, zero,
console, time, sysname; `/proc` with meminfo, uptime, cpuinfo; `/net` with
arp, iface, tcp/stats) generate their content on each read with no
pre-computed state and no heap allocation. The VFS mount table uses
longest-prefix matching to dispatch reads to the correct filesystem vtable.
The result: `cat /proc/meminfo` or `cat /net/tcp/stats` works the same way
whether called from a shell task or the REST API, with no special-purpose
monitoring code.

What Mazu explicitly does not take: Linux's loadable modules, VFS page
cache, socket layer, and process isolation model; Plan 9's network stack
and user-space server model. The kernel runs all tasks in a single shared
page table (kernel regions identity-mapped, user pages at fixed VAs within
the same table). Disk-backed SFS uses a block buffer cache; synthetic and
RAM filesystems are uncached. Networking is a direct function interface,
not a socket API. These omissions are permanent design choices, not items
on a backlog.

## SMP as a structural property

When SMP support is added as a configuration option on top of a
single-core design, concurrency bugs hide until someone enables the
second core. Mazu inverts this: SMP shapes the data structures, and
single-core is the `MAX_CPUS=1` special case selected by leaving
`CONFIG_SMP` unset.

Every hart owns its own run queue, sorted callout list, timer deadline,
and interrupt counters. The `struct pcpu` is cache-line aligned (64
bytes) and accessed via the `gp` register in a single instruction; no
hash table, no array index. Merged deadline management
(`min(timer, preempt, watchdog)`) reduces hardware timer reprogramming
to the cases where the earliest deadline actually changes. Lock
ordering is enumerated at compile time as a fixed level hierarchy
(IRQ < PROC < FD < SIG < WAITQ < TCP < SCHED < CALLOUT < ALLOC) and
enforced at runtime through lockdep assertions
(`DEBUG_ASSERT` on every acquire and release in debug builds; zero
cost in release).

The scheduler is unconditionally preemptive: `CONFIG_SCHED_PREEMPTIVE` is
mandatory, and the build fails if someone tries to disable it. Every trap
exit drains `need_resched` via an atomic exchange. EEVDF provides fairness
within priority levels. EDF deadline scheduling with admission control and
budget enforcement targets hard-deadline workloads. Mixed-criticality
scheduling domains partition CPU time between high-criticality (control)
and low-criticality (web/telemetry) task groups with automatic escalation
and recovery.

## Networking and real-time in the same kernel

A common RTOS approach to networking is a separately-maintained IP stack
(lwIP, or a BSD-derived layer) integrated with the scheduler through an
adapter that bridges two different threading and memory models. That
integration boundary can become a source of priority inversions, lock
contention, and latency surprises.

Mazu puts TCP/IP inside the kernel under the same lock discipline as
everything else. The receive path is a preemptible scheduler task that
drains the virtio-net ring buffer, demultiplexes through ARP/ICMP/TCP, and
hands data to connection-specific circular buffers, all under the same
lockdep enforcement that governs the scheduler. TCP connections live in a
pool allocator (no external fragmentation, O(1) alloc/free). Per-IP
connection limits (`TCP_MAX_CONNS_PER_IP`, `TCP_MAX_SYN_RCVD_PER_IP`) bound
resource consumption under SYN floods without a separate firewall. The
HTTP server runs as a normal preemptible task that yields its quantum like
any other; a deadline-scheduled task on the same hart preempts it on the
next trap exit.

The design goal is that bounded latency and network correctness share the
same scheduler, the same lock hierarchy, and the same per-CPU state rather
than living in separate subsystems that must be reconciled at runtime.

## Programming style

This section covers the *design-level* abstractions that shape the
codebase. For *surface-level* conventions (naming, formatting,
indentation, header guards, comment markers, commit messages),
see [`CONTRIBUTING.md`](../CONTRIBUTING.md). The design abstractions
below presuppose those conventions; together they define what
"reading like Mazu code" means.

The C programming style emphasizes correctness and readability
through abstractions that differ from the C standard library, heavily
inspired by Chris Wellons' writing (see
[nullprogram.com](https://nullprogram.com/)). Core elements:

- [Length-prefixed strings](https://nullprogram.com/blog/2023/10/08/)
  (`struct str { char *dat; sz len; }`) instead of null-terminated
  strings. `strlen`, `strcpy`, and friends are absent from the
  codebase by construction.
- Structured return values: either a success with a value or an
  error with a code. Error codes never share the return-value space,
  so callers can never confuse a valid result with `-EINVAL`.
- Separate types for read-only (`byte_view`, `str`), read-write
  (`byte_array`), and appendable (`byte_buf`, `str_buf`) memory
  regions. Mutability is encoded in the type, not in a comment or
  convention.
- Arena allocators for short-lived storage (e.g., per-request HTTP
  parsing). A single bulk-free at end-of-request avoids per-object
  bookkeeping.
- Pool allocators for fixed-size objects (TCP connections, send
  buffers). O(1) allocation with no external fragmentation.

These abstractions carry semantic information in the type system. The
mutability hierarchy eliminates entire classes of buffer-overflow and
use-after-free bugs while keeping the code readable enough for
low-level maintenance. The ramfs (`kernel/fs/ramfs.c`) and the IP
layer (`kernel/net/ip.c`) are representative examples; new code is
expected to follow the same patterns.
