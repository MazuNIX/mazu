/* SPDX-License-Identifier: MIT */
/* POSIX sysconf() names and feature-test macros for Mazu.
 *
 * Only features actually implemented by Mazu are advertised.
 * Unimplemented _SC_ names return -EINVAL from sys_sysconf().
 */

#ifndef MAZU_SYSCONF_H
#define MAZU_SYSCONF_H

#include <mazu/base.h>

/* Feature-test macros: only defined for implemented POSIX features.
 * Value 200809L indicates POSIX.1-2008 conformance for that feature where
 * Mazu's behavior matches POSIX semantics. Where the kernel ABI is reduced
 * (Mazu-specific scalar arguments instead of POSIX struct shapes) the
 * value is set to 1 to advertise feature presence without claiming exact
 * POSIX-2008 conformance.
 */
#define _POSIX_SPAWN 200809L
#define _POSIX_PIPE_BUF 512 /* POSIX-mandated minimum */
#define _POSIX_FSYNC 200809L
#define _POSIX_SYNCHRONIZED_IO 200809L

/* PSE51 feature-test macros: present features only.  See docs/pse51-matrix.md
 * for the full classification (implemented vs implemented-with-mazu-abi).
 */
#define _POSIX_TIMERS 1 /* SYS_TIMER_*; sigevent reduced */
#define _POSIX_MONOTONIC_CLOCK 200809L
#define _POSIX_PRIORITY_SCHEDULING 1 /* SYS_SCHED_SETPARAM/GETPARAM */
#define _POSIX_SEMAPHORES 200809L
#define _POSIX_BARRIERS 200809L
#define _POSIX_READER_WRITER_LOCKS 1 /* timed forms use ms ABI */
#define _POSIX_THREAD_PRIO_INHERIT 200809L
#define _POSIX_MESSAGE_PASSING 1 /* anonymous queues only */
#define _POSIX_CPUTIME 200809L
#define _POSIX_THREAD_CPUTIME 200809L
#define _POSIX_THREADS 1 /* SYS_THREAD_*; PROC_THREAD_MAX = 4 */
#define _POSIX_TIMEOUTS 200809L
#define _POSIX_CLOCK_SELECTION 200809L
/* _POSIX_REALTIME_SIGNALS reports the wait-for-signal API set
 * (sigsuspend, sigtimedwait, sigwait, sigwaitinfo). Mazu also has a
 * bounded sigqueue-style payload path, but it is exposed through a
 * Mazu-specific ABI extension rather than the full POSIX siginfo /
 * SA_SIGINFO surface, so this remains the subset value 1.
 */
#define _POSIX_REALTIME_SIGNALS 1
/* _POSIX_SPIN_LOCKS is intentionally not defined: there is no
 * userspace pthread_spin_* surface yet, only kernel-internal spinlocks.
 * Advertising it would let an app gate on the macro and call absent APIs.
 * _SC_SPIN_LOCKS reports -1 to match.
 */

/* sysconf() name constants.  Subset of POSIX _SC_ names relevant to Mazu. */
#define _SC_PAGE_SIZE 0
#define _SC_PAGESIZE _SC_PAGE_SIZE /* alias */
#define _SC_OPEN_MAX 1
#define _SC_NPROCESSORS_CONF 2
#define _SC_NPROCESSORS_ONLN 3
#define _SC_PIPE_BUF 4
#define _SC_CHILD_MAX 5
#define _SC_MEMLOCK 6

/* PSE51 option-reporting names.  Each returns the matching
 * _POSIX_* feature-test value when the option is implemented, or -1 when
 * it is not.  No name returns 0 (POSIX reserves 0 for "implemented but
 * no value"; Mazu does not have such a case).
 */
#define _SC_TIMERS 7
#define _SC_MONOTONIC_CLOCK 8
#define _SC_PRIORITY_SCHEDULING 9
#define _SC_SEMAPHORES 10
#define _SC_BARRIERS 11
#define _SC_READER_WRITER_LOCKS 12
#define _SC_THREAD_PRIORITY_INHERIT 13
#define _SC_MESSAGE_PASSING 14
#define _SC_SPIN_LOCKS 15
#define _SC_REALTIME_SIGNALS \
    16 /* sysconf returns _POSIX_REALTIME_SIGNALS (1) */
#define _SC_THREADS 17
#define _SC_THREAD_CPUTIME 18
#define _SC_CPUTIME 19
#define _SC_CLOCK_SELECTION 20
#define _SC_TIMEOUTS 21
#define _SC_SYNCHRONIZED_IO 22

#define _SC_NR 23 /* total number of sysconf names */

/* Kernel-callable sysconf query.  Returns the value for the given _SC_
 * name, or -EINVAL for unknown names.
 */
i64 sys_sysconf_query(i64 name);

#endif /* MAZU_SYSCONF_H */
