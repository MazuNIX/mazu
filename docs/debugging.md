# Debugging and verification

## GDB

QEMU exposes a GDB stub:

```bash
GDB=1 make run
riscv-none-elf-gdb build/kernel.elf
# inside gdb:
target remote localhost:1234
```

QEMU pauses at startup until GDB connects.

## Runtime verification

Mazu includes several runtime verification mechanisms. Each is gated
independently; see the per-section notes for which build flag controls
it.

### Lock ordering enforcement

`kernel/lockdep.h`. Gated on `__DEBUG__ > 0` and compiled out entirely
in release builds. A per-CPU `held_locks` bitmask tracks which
lock levels are currently held. `lockdep_acquire()` asserts that no
same-or-higher-level lock is held before acquiring; `lockdep_release()`
asserts the lock was actually held (catches double-release). The lock
hierarchy is:

```
IRQ(0) < PROC(1) < FD(2) < SIG(3) < WAITQ(4) < TCP(5) < SCHED(6) <
CALLOUT(7) < ALLOC(8)
```

Violations trigger `DEBUG_ASSERT` in debug builds.

### Scheduler invariant checking

`kernel/sched/core.c`, gated on `__DEBUG__ > 0`.
`sched_check_invariants()` runs at the end of every context switch
and verifies three properties:

- MutualExclusion: the selected task is in `RUNNING` state.
- SingleExecution: no other hart is running the same task.
- QueueConsistency: run queue bitmap matches actual queue occupancy,
  all queued tasks are in `READY` state.

Uses `spin_trylock` to avoid deadlock during the check.

### Callout telemetry

`kernel/timer/callout.c`. Always built; not debug-gated. Per-CPU
lateness histogram bins track how late each callout fires relative to
its deadline. Six bins from 0-10 us to >100 ms. Aggregated via
`callout_get_stats()` and exposed in `/api/stats` JSON. Callbacks more
than 100 us late are counted as missed.

### UBSan trap mode

Gated on `CONFIG_UBSAN=y`. GCC `-fsanitize=undefined` with
`-fsanitize-trap=all`, no runtime library needed. On undefined
behavior, the compiler inserts `ebreak`, which triggers the trap
handler (`scause=3`). The handler prints `sepc`, a backtrace, and
halts. Catches signed overflow, shift-out-of-range, divide-by-zero,
null dereference (compiler-proven), unreachable code, VLA bound, and
misaligned pointer use. Compiled out entirely when disabled.

### Self-test framework

`lib/selftest.c`, gated on `CONFIG_SEMIHOSTING=y`. Linker-section-
based test registration via `DEFINE_SELFTEST(name, fn)` (see
`include/mazu/selftest.h`). Tests are collected into the `.selftest`
section and iterated by `run_selftests()`. Boot-mode selection via
QEMU `-append "selftest"` triggers self-test mode: run tests, exit
with pass/fail code.

### Semihosting console

`arch/riscv64/semihost.c`. RISC-V semihosting protocol for host
communication, enabled by `CONFIG_SEMIHOSTING=y`. Provides early
console output (before UART init), host file I/O, and clean QEMU exit
codes. The 3-instruction trap sequence (`slli` / `ebreak` / `srai`) is
recognized by QEMU when started with
`-semihosting-config enable=on,target=native`. Compiled out entirely
when disabled. The `printk` console backend uses semihosting for
early output; once `arch_init()` runs, `uart_console_init()` calls
`print_register_console(uart_console_write)` so subsequent output
flows through the UART.
