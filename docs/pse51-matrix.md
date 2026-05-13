# PSE51 Compatibility Matrix

Status of every PSE51-facing syscall and feature in Mazu.

PSE51 (POSIX.13 Minimal Realtime System Profile) describes a single-process,
threaded, no-filesystem environment. Mazu deliberately ships supersets of
that profile (real filesystem, `SYS_SPAWN` / `SYS_WAIT`, multiple PIDs,
synthetic VFS, web server). Reading "PSE51" in Mazu documentation means
"PSE51-oriented portability layer", not "exact profile conformance".

The honest top-level framing of the user-visible environment is closer to
PSE52 (Realtime Controller System Profile) than PSE51, because of the
filesystem and multi-process model. This document tracks how individual
PSE51 interfaces fare on top of that base.

## Conformance status

Mazu's PSE51-oriented userspace ABI is feature-complete: every
mandatory PSE51 syscall is wired and exercised by selftests, and
the `pthread_attr_*` family ships as a header-only library at
`include/mazu/pthread.h` on top of the kernel surface.

Deliberate deviations (not fix-it gaps):

- **`shm_open` / `shm_unlink`** (`_POSIX_SHARED_MEMORY_OBJECTS`).
  Structurally redundant under Mazu's shared page table.
- **`SYS_SPAWN`, `SYS_WAIT`, multiple PIDs**, real filesystem,
  web server. PSE51 is single-process; Mazu is bounded multi-
  process by design.

Closed gaps: pthread_create / join / detach / exit /
setschedparam / getschedparam / kill / cancel / sigmask,
sigsuspend, sigtimedwait, sigwait, sigwaitinfo, sigprocmask,
mlock / munlock range form, fsync / fdatasync,
sched_setscheduler / _getscheduler, SIGEV_THREAD_ID timer
delivery, CLOCK_THREAD_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID,
absolute-timespec timed waits, thread-exit trampoline (with
magic verification), pthread_attr_* family (header-only
library at `include/mazu/pthread.h` plus explicit-priority
spawn via `SYS_THREAD_CREATE_EXPLICIT`.

Public docs should describe the implementation as "bounded
PSE51-compatible userspace core". The subset framing is honest
because Mazu intentionally exceeds PSE51 with multi-process and
filesystem support.

## What Mazu ships today (PSE51-relevant)

The following PSE51 services are present and exercised by selftests
(`tests/tests-pse51.c` as the consolidated profile suite, with
subsystem regression detail in `tests/tests-syscall.c`,
`tests/tests-mqueue.c`, `tests/tests-posix_timer.c`,
`tests/tests-rwlock.c`, `tests/tests-barrier.c`,
`tests/tests-condvar.c`, `tests/tests-semaphore.c`,
`tests/tests-mutex.c`, `tests/tests-clock.c`):

- `clock_gettime`, `clock_getres`, `nanosleep` (with kernel-reported
  `EINTR` remainder).
- `pthread_mutex_lock` / `_trylock` / `_unlock` with priority
  inheritance and direct handover.
- `pthread_cond_wait` / `_signal` / `_broadcast` and a relative-timeout
  `cond_timedwait`.
- `sem_init` / `_wait` / `_trywait` / `_post` and a relative-timeout
  `sem_timedwait`.
- `pthread_barrier_init` / `_wait` / `_destroy`.
- `pthread_rwlock_*` including relative-timeout timed forms.
- POSIX timers (pool-allocated, callout-backed, overrun reported).
- POSIX message queues (anonymous, in-kernel pool).
- Counting-semaphore-style `sched_yield`, `sched_get_priority_min` /
  `_max`, scalar `sched_setparam` / `_getparam`.
- `mlockall` / `munlockall` no-op success.
- `sysconf` option reporting for the implemented PSE51 services
  (returns `_POSIX_*` for present features, -1 for absent ones).

## Status legend

| Status | Meaning |
|---|---|
| implemented | Available with POSIX-equivalent semantics. |
| implemented-with-mazu-abi | Available, but the syscall ABI differs from POSIX (typically scalar millisecond arguments instead of `struct timespec`, or reduced `sigevent` shapes). User-space libc shims may still expose POSIX-shaped C entry points. |
| stubbed | Syscall number is registered; the handler currently returns `-ENOSYS` or a degenerate constant. Listed so callers can detect unsupported features at runtime. |
| out-of-profile | Mazu intentionally exceeds PSE51 here (filesystem, multi-process, etc.). Listed for transparency, not as a deficit. |
| not-applicable | The interface does not fit Mazu's design (single shared address space, no MMU isolation between processes for memory, no fork). |

## Time and clocks

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `clock_gettime` | `SYS_CLOCK_GETTIME` | implemented | `CLOCK_MONOTONIC`, `CLOCK_REALTIME`, `CLOCK_THREAD_CPUTIME_ID`, `CLOCK_PROCESS_CPUTIME_ID`. |
| `clock_getres` | `SYS_CLOCK_GETRES` | implemented | Resolution derives from the timebase frequency; sub-millisecond on QEMU `virt`. |
| `clock_settime` | (none) | not-applicable | Realtime clock is anchored to boot ticks; no settable wall clock yet. |
| `clock_nanosleep` | (none) | stubbed | The relative form is covered by `nanosleep`; the absolute form is tracked under PSE51 ABI alignment work. |
| `nanosleep` | `SYS_NANOSLEEP` | implemented-with-mazu-abi | Accepts `struct timespec`. On `EINTR` the kernel writes the unexpired remainder to `*rem` when `rem` is non-NULL (best-effort: a bad `rem` pointer does not mask the `EINTR` return). On normal completion `*rem` is unmodified. `tv_sec` is bounded against u64 overflow to keep the kernel-side ns/ms conversion safe. |

## Synchronization (kernel handles)

User space holds `i32` handle values; the kernel side is the per-process
sync handle table (`kernel/sync/sync_handle.c`).

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `pthread_mutex_init` / `_lock` / `_trylock` / `_unlock` | `SYS_MUTEX_INIT` / `_LOCK` / `_TRYLOCK` / `_UNLOCK` | implemented | Priority-inheritance, direct handover, no barging. No `pthread_mutex_destroy` syscall yet; handles are reaped on process exit. |
| `pthread_mutex_timedlock` | (none) | stubbed | Not exposed; bounded callers use `sem_timedwait` or `cond_timedwait`. |
| `pthread_cond_init` / `_signal` / `_broadcast` / `_wait` | `SYS_COND_INIT` / `_SIGNAL` / `_BROADCAST` / `_WAIT` | implemented | Timed wait below. No `pthread_cond_destroy` syscall yet. |
| `pthread_cond_timedwait` | `SYS_COND_TIMEDWAIT` | implemented | ABI takes an absolute `struct timespec *` (CLOCK_MONOTONIC); the conversion to a relative timeout happens at syscall entry to avoid the libc-shim race. |
| `sem_init` / `_wait` / `_trywait` / `_post` | `SYS_SEM_INIT` / `_WAIT` / `_TRYWAIT` / `_POST` | implemented | Counting semaphore with FIFO direct handover. |
| `sem_timedwait` | `SYS_SEM_TIMEDWAIT` | implemented | Absolute `struct timespec *`; converted in-kernel. |
| `pthread_barrier_init` / `_wait` / `_destroy` | `SYS_BARRIER_INIT` / `_WAIT` / `_DESTROY` | implemented | `_destroy` returns `-EBUSY` when waiters are present. |
| `pthread_rwlock_init` / `_rdlock` / `_wrlock` / `_tryrdlock` / `_trywrlock` / `_unlock` / `_destroy` | `SYS_RWLOCK_*` | implemented | Writer-preference; standard `EBUSY` semantics. |
| `pthread_rwlock_timedrdlock` / `_timedwrlock` | `SYS_RWLOCK_TIMEDRDLOCK` / `_TIMEDWRLOCK` | implemented | Absolute `struct timespec *`; converted in-kernel. |

## Threads

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `pthread_self` | `SYS_THREAD_SELF` | implemented | Returns the caller's `CAP_TYPE_THREAD` small-int handle. |
| `pthread_create` | `SYS_THREAD_CREATE` / `SYS_THREAD_CREATE_EXPLICIT` | implemented | PROC_THREAD_MAX = 4. Slot reservation under `proc_table_lock`, per-thread stack VA inside the proc slot. Returns a fresh `CAP_TYPE_THREAD` handle. `SYS_THREAD_CREATE` keeps the original two-argument ABI and always inherits the creator's base priority. `SYS_THREAD_CREATE_EXPLICIT` is the opt-in extension: a2 == 0 inherits, values in [1, CONFIG_SCHED_NPRIO] set explicit priority (a2 - 1), a value above CONFIG_SCHED_NPRIO returns EINVAL, and a value that would exceed the creator's base priority returns EPERM. |
| `pthread_join` | `SYS_THREAD_JOIN` | implemented | Blocks on `target->td_join_wq`; atomically claims `EXITED -> REAPED` via cmpxchg before reaping. EDEADLK on self-join, ESRCH on unknown thread handle, EINVAL on detached/already-reaped, EINTR on cancellation. |
| `pthread_detach` | `SYS_THREAD_DETACH` | implemented | Tries `JOINABLE -> DETACHED` first; if the target already exited, claims `EXITED -> REAPED` and reaps inline. Either claim wakes pending joiners. |
| `pthread_exit` | `SYS_THREAD_EXIT` | implemented | Last-thread exit collapses into `proc_exit`; non-last exit unwinds the thread's robust futex list. A user thread that returns from its entry function lands on the per-process unmapped trampoline at `signal_trampoline_pc(p)+4`; the trap handler synthesizes `SYS_THREAD_EXIT(0)`, so an implicit return is equivalent to an explicit pthread_exit. |
| `pthread_setschedparam` / `_getschedparam` | `SYS_THREAD_SETSCHEDPARAM` / `_GETSCHEDPARAM` | implemented-with-mazu-abi | Take a `CAP_TYPE_THREAD` handle (0 = self) and a scalar priority. Privilege bound: cannot raise above caller's own base priority. |
| `pthread_attr_*` | (libc) | implemented | Header-only library at `include/mazu/pthread.h`. Covers `pthread_attr_init` / `_destroy` / `_setdetachstate` / `_getdetachstate` / `_setinheritsched` / `_getinheritsched` / `_setschedpolicy` / `_getschedpolicy` / `_setschedparam` / `_getschedparam` / `_setstacksize` / `_getstacksize` / `_setstack` / `_getstack`. All functions return positive errno on failure (POSIX convention). Stack address selection is delegated to the kernel (shared-VA model); `pthread_attr_setstack` always returns `ENOTSUP`, and `pthread_attr_setstacksize` succeeds only for `USER_STACK_SIZE`, so callers do not observe a stack contract the kernel cannot honor. The accompanying `pthread_attr_resolve_create_syscall` and `pthread_attr_resolve_prio_arg` helpers produce the syscall number and a2 encoding for the future `pthread_create` wrapper. |
| `pthread_spin_init` / `_lock` / `_trylock` / `_unlock` / `_destroy` | (none) | stubbed | Mazu has kernel-internal spinlocks, but no userspace-visible busy-wait primitive. The `_POSIX_SPIN_LOCKS` macro is therefore intentionally *not* defined and `_SC_SPIN_LOCKS` returns -1 — advertising it would let an app gate on the macro and call absent APIs. Expect a libc-side implementation backed by a futex once threads land, not a kernel syscall. |
| `pthread_cancel` / `pthread_setcancelstate` / `pthread_testcancel` | `SYS_THREAD_CANCEL` / `SYS_THREAD_SETCANCELSTATE` / `SYS_THREAD_TESTCANCEL` | implemented | Deferred cancellation: pthread_cancel sets `td_cancel_pending`; the target observes the bit at the next cancellation point and exits with code -ECANCELED. ASYNC type is treated as DEFERRED because Mazu has no in-kernel cancellation points other than blocking syscalls. |

## Signals

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `kill` | `SYS_KILL` | implemented | Process-directed, in-band delivery via the trap exit path. |
| `sigaction` | `SYS_SIGACTION` | implemented | Per-process disposition. `sa_mask` is a `u32` bitmask, not `sigset_t`. |
| `sigreturn` | `SYS_SIGRETURN` | implemented | Cookie-validated frame teardown. |
| `pthread_sigmask` | `SYS_PTHREAD_SIGMASK` | implemented | Same wire shape as `SYS_SIGPROCMASK`; both operate on the calling thread's `td_sig.blocked`. Distinct syscall numbers so libc can keep `pthread_sigmask` and `sigprocmask` as separate ABI surfaces. |
| `pthread_kill` | `SYS_PTHREAD_KILL` | implemented | Thread-directed signal: bit lands on the named thread's `td_sig.pending` rather than the per-proc `proc_pending` mask. Takes a `CAP_TYPE_THREAD` handle. SIGKILL rejected with EINVAL (must be process-wide). |
| `sigsuspend` | `SYS_SIGSUSPEND` | implemented | Replace blocked mask with the supplied set, yield-loop until a deliverable signal arrives, restore prior mask, return EINTR. |
| `sigtimedwait` / `sigwait` / `sigwaitinfo` | `SYS_SIGTIMEDWAIT` | implemented-with-mazu-abi | Block until any signal in the supplied set is pending; dequeue without invoking the handler; return signo. Honors `struct timespec *` timeout (NULL = wait forever; expired = EAGAIN). Mazu ABI also accepts an optional payload-out pointer in `a3`; queued `sigqueue` values are surfaced there when present. |
| `sigqueue` value delivery | `SYS_SIGQUEUE` | implemented-with-mazu-abi | Process-directed queued values use a bounded per-signal ring (`SIGQUEUE_MAX_PER_SIGNO` entries per signo, with one extra internal slot reserved so a single in-flight `SYS_SIGTIMEDWAIT` consumer can losslessly roll back a dequeued payload if `copy_to_user` faults after the lock was dropped). Lossless rollback is guaranteed for the single-consumer case; if multiple threads simultaneously fault their rollbacks for the same signo, the helper drops one payload as defense-in-depth and surfaces a plain pending instance so the signal stays observable. Plain `kill` remains level-style and is tracked on a separate `proc_pending_plain` mask so it cannot be silently swallowed by a queued instance of the same signo. Queued payloads are observable via `SYS_SIGTIMEDWAIT` and friends, while one-argument signal handlers still receive only signo. |
| `sigprocmask` (single-threaded) | `SYS_SIGPROCMASK` | implemented | Modify-and-return-old of the calling thread's `td_sig.blocked` under `sig_lock`. SIGKILL cannot be blocked. The mask migrated from per-process to per-thread when `SYS_PTHREAD_SIGMASK` landed; both syscalls now share the same backing field with distinct wire shapes so libc can keep them as separate ABI surfaces. |
| `raise` | (libc) | not-applicable | Library-level wrapper for `kill(getpid(), sig)`; covered by `SYS_KILL`. |

## POSIX timers

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `timer_create` | `SYS_TIMER_CREATE` | implemented-with-mazu-abi | Pool-allocated (8 timers per process). Signal number is fixed to `SIGALRM`; the per-call target thread (`SIGEV_THREAD_ID`) is supplied via `posix_timer_settime`'s new thread-handle parameter (a3 of `SYS_TIMER_SETTIME`); pass 0 for process-directed delivery. If the targeted thread has already exited at expiry, the signal is silently dropped (POSIX strict). |
| `timer_settime` | `SYS_TIMER_SETTIME` | implemented-with-mazu-abi | ABI takes `u64 value_ms, u64 interval_ms` instead of `struct itimerspec`. `value_ms == 0` disarms (POSIX semantics). |
| `timer_gettime` | `SYS_TIMER_GETTIME` | implemented-with-mazu-abi | Returns remaining milliseconds as a scalar. |
| `timer_getoverrun` | `SYS_TIMER_GETOVERRUN` | implemented | Increments only while the previous `SIGALRM` is still pending (POSIX overrun semantics). |
| `timer_delete` | `SYS_TIMER_DELETE` | implemented | `callout_cancel_sync` is performed in the delete path. |

## Message queues

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `mq_open` | `SYS_MQ_OPEN` | implemented-with-mazu-abi | Anonymous queues only: ABI takes `(max_msgs, max_msg_size)` and returns a handle. There is no name and no `mq_unlink`. Inherited across `SYS_SPAWN`. |
| `mq_close` | `SYS_MQ_CLOSE` | implemented | |
| `mq_send` | `SYS_MQ_SEND` | implemented | Non-blocking on full queue. |
| `mq_receive` | `SYS_MQ_RECEIVE` | implemented | |
| `mq_timedreceive` | `SYS_MQ_TIMEDRECEIVE` | implemented | Absolute `struct timespec *`; converted in-kernel. |
| `mq_timedsend` | (none) | stubbed | Not exposed; non-blocking `mq_send` is the only send form. |
| `mq_notify` | (none) | not-applicable | Out of scope for the bounded RT model. |
| `mq_unlink` | (none) | not-applicable | Anonymous queues (no namespace). |

## Scheduling

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `sched_yield` | `SYS_SCHED_YIELD` | implemented | |
| `sched_get_priority_min` | `SYS_SCHED_GET_PRIORITY_MIN` | implemented | Returns `SCHED_PRIO_IDLE`. |
| `sched_get_priority_max` | `SYS_SCHED_GET_PRIORITY_MAX` | implemented | Returns `CONFIG_SCHED_NPRIO - 1`. |
| `sched_setparam` | `SYS_SCHED_SETPARAM` | implemented-with-mazu-abi | ABI takes a scalar priority `i32`. Cannot raise above caller's base priority. |
| `sched_getparam` | `SYS_SCHED_GETPARAM` | implemented-with-mazu-abi | Returns scalar base priority. |
| `sched_setscheduler` / `_getscheduler` | `SYS_SCHED_SETSCHEDULER` / `_GETSCHEDULER` | implemented-with-mazu-abi | Accepts `SCHED_FIFO` / `SCHED_OTHER` / `SCHED_RR` and coerces all three to `SCHED_FIFO` since Mazu honors a single effective policy for normal threads. The matching getter always reports `SCHED_FIFO`. `SYS_SCHED_SETATTR` / `_GETATTR` cover the deadline path. |
| `sched_setaffinity` / `_getaffinity` | `SYS_SCHED_SETAFFINITY` / `_GETAFFINITY` | implemented | Linux-style `cpumask`. Out of strict PSE51, retained for SMP control. |
| `sched_rr_get_interval` | (none) | not-applicable | Mazu has no round-robin policy. |

## Memory locking

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `mlockall` | `SYS_MLOCKALL` | implemented | All physical memory is resident on bare metal; the syscall is a no-op success. |
| `munlockall` | `SYS_MUNLOCKALL` | implemented | No-op success (matches `mlockall`). |
| `mlock` / `munlock` | `SYS_MLOCK` / `SYS_MUNLOCK` | implemented | Range form. Validates `(addr, len)` is non-empty, non-wrapping, and lies inside a registered VMA; returns success without touching page tables. |
| `mmap` / `munmap` / `mprotect` | (none) | not-applicable | No user-space mapping facility; address space is arranged at proc creation, with a single shared page table. PSE51 requires `_POSIX_MAPPED_FILES` for memory-mapped files only; that requirement is incompatible with Mazu's shared-page-table design and is a deliberate deviation. |
| `shm_open` / `shm_unlink` | (none) | not-applicable | Shared memory is implicit in the shared address space; the namespaced `_POSIX_SHARED_MEMORY_OBJECTS` API is structurally redundant under one page table. Deliberate deviation; deviates from strict PSE51 conformance. |

## Synchronized I/O

PSE51 requires `_POSIX_FSYNC` (and recommends `_POSIX_SYNCHRONIZED_IO`).
Mazu has a real filesystem, so the gap shows up here.

| Interface (POSIX) | Mazu syscall | Status | Notes |
|---|---|---|---|
| `fsync` | `SYS_FSYNC` | implemented-with-mazu-abi | Validates the FD is open, returns success. The disk-backed SFS already commits writes synchronously inside `kernel/fs/sfs.c`; the synthetic and RAM filesystems have no backing store. |
| `fdatasync` | `SYS_FDATASYNC` | implemented-with-mazu-abi | Same backing logic as `fsync` for Mazu (no separate metadata vs data path). |
| `O_SYNC` / `O_DSYNC` open flags | (none) | stubbed | Open flags are not parsed today. |

## Filesystem and process model

These interfaces exceed strict PSE51. They are listed here for completeness
so that "missing from PSE51 matrix" does not imply "missing from Mazu".

| Interface | Mazu syscall | Status |
|---|---|---|
| `open` / `close` / `read` / `write` / `lseek` / `dup` / `dup2` | `SYS_OPEN` / `_CLOSE` / `_READ` / `_WRITE` / `_LSEEK` / `_DUP` / `_DUP2` | out-of-profile |
| `chdir` / `getcwd` | `SYS_CHDIR` / `_GETCWD` | out-of-profile |
| `pipe` | `SYS_PIPE` | out-of-profile |
| `posix_spawn` family | `SYS_SPAWN` | out-of-profile |
| `waitpid` | `SYS_WAIT` | out-of-profile |
| `getpid` / `getppid` | `SYS_GETPID` / `_GETPPID` | out-of-profile |
| `_exit` | `SYS_EXIT` | out-of-profile |

## Feature-test reporting (`sysconf`)

`SYS_SYSCONF` covers a deliberate subset of `_SC_*` names; any unhandled
name returns `-EINVAL`. The implemented set today:

| `_SC_*` | Returns |
|---|---|
| `_SC_PAGE_SIZE` / `_SC_PAGESIZE` | `PAGE_SIZE` |
| `_SC_OPEN_MAX` | `PROC_FD_MAX` |
| `_SC_NPROCESSORS_CONF` / `_SC_NPROCESSORS_ONLN` | `nr_cpus_online` |
| `_SC_PIPE_BUF` | `PIPE_BUF_SIZE` |
| `_SC_CHILD_MAX` | `PROC_MAX - 1` |
| `_SC_MEMLOCK` | `0` (locking is implicit) |

PSE51 option-reporting names (each returns the matching `_POSIX_*`
feature-test value when implemented, or `-1` when absent):

| `_SC_*` | Returns | Meaning |
|---|---|---|
| `_SC_TIMERS` | `_POSIX_TIMERS` (1) | POSIX timers present, sigevent reduced. |
| `_SC_MONOTONIC_CLOCK` | `_POSIX_MONOTONIC_CLOCK` (200809L) | Full POSIX semantics. |
| `_SC_PRIORITY_SCHEDULING` | `_POSIX_PRIORITY_SCHEDULING` (1) | Scalar priority via `SYS_SCHED_SETPARAM`. |
| `_SC_SEMAPHORES` | `_POSIX_SEMAPHORES` (200809L) | POSIX semantics; named-semaphore namespace omitted. |
| `_SC_BARRIERS` | `_POSIX_BARRIERS` (200809L) | Full POSIX semantics. |
| `_SC_READER_WRITER_LOCKS` | `_POSIX_READER_WRITER_LOCKS` (1) | Timed forms use the relative-ms ABI. |
| `_SC_THREAD_PRIORITY_INHERIT` | `_POSIX_THREAD_PRIO_INHERIT` (200809L) | PI mutex is the only mutex flavor. |
| `_SC_MESSAGE_PASSING` | `_POSIX_MESSAGE_PASSING` (1) | Anonymous queues only. |
| `_SC_SPIN_LOCKS` | -1 | No userspace `pthread_spin_*` surface today, so the macro is intentionally not defined. |
| `_SC_REALTIME_SIGNALS` | `_POSIX_REALTIME_SIGNALS` (1) | Wait-for-signal API is present. Bounded `sigqueue` payload delivery exists, but via a Mazu-specific extension rather than the full POSIX `siginfo_t` / `SA_SIGINFO` contract. |
| `_SC_THREADS` | `_POSIX_THREADS` (1) | `SYS_THREAD_*` present; `PROC_THREAD_MAX = 4`. |
| `_SC_THREAD_CPUTIME` | `_POSIX_THREAD_CPUTIME` (200809L) | `clock_gettime(CLOCK_THREAD_CPUTIME_ID, ...)` measures the calling thread's accumulated CPU time. |
| `_SC_CPUTIME` | `_POSIX_CPUTIME` (200809L) | `clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ...)` returns the sum across all live threads in the calling process. |
| `_SC_CLOCK_SELECTION` | -1 | No `clock_nanosleep`. |

## Deliberate deviations from PSE51

The following are intentional and will not be removed by future PSE51
work. They are part of the product, not optional compatibility extensions.

- Real filesystem, `SYS_SPAWN`, `SYS_WAIT`, multiple PIDs, `getpid` /
  `getppid`. PSE51 is single-process; Mazu is bounded multi-process.
- Web shell, HTTP server, WebSocket, SSE. PSE51 is platform-neutral; Mazu
  exists to serve interactive web workloads.
- Single shared page table with VMA-based access control rather than
  per-process MMU isolation between user processes (capabilities mediate
  kernel-object access; raw memory is shared by design).
- `cpumask`-based affinity syscalls and EDF deadline scheduling
  (`SYS_SCHED_SETATTR` / `_GETATTR`). Outside PSE51, retained for SMP
  control and mixed-criticality workloads.

## Gating future "PSE51 complete" milestones

The bounded multi-threaded process model is in place: per-thread
state migration (signal pending/blocked, signal-frame chain, robust
futex list, errno TLS), the user-visible pthread surface
(`SYS_THREAD_CREATE` and friends, `PROC_THREAD_MAX = 4`), and the
`pthread_attr_*` library have all landed. A future user-mode
`pthread_create` wrapper can honor `PTHREAD_EXPLICIT_SCHED` without
the `SETSCHEDPARAM`-after-create race window by switching from
`SYS_THREAD_CREATE` to `SYS_THREAD_CREATE_EXPLICIT` and passing the
resolved priority in a2 as (prio + 1).
