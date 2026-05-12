/* SPDX-License-Identifier: MIT */
/* Syscall numbers for Mazu user-space.
 *
 * ABI: a7 = syscall number, a0-a5 = arguments, a0 = return value.
 * User code issues an ecall instruction; the trap handler dispatches
 * to the appropriate kernel function via syscall_dispatch().
 */

#ifndef MAZU_SYSCALL_H
#define MAZU_SYSCALL_H

#define SYS_OPEN 0
#define SYS_CLOSE 1
#define SYS_READ 2
#define SYS_WRITE 3
#define SYS_STAT 4
#define SYS_EXIT 5
#define SYS_YIELD 6
#define SYS_TIME 7
#define SYS_SPAWN 8
#define SYS_WAIT 9
#define SYS_GETPID 10
#define SYS_GETPPID 11
#define SYS_DUP 12
#define SYS_DUP2 13
#define SYS_LSEEK 14
#define SYS_CHDIR 15
#define SYS_GETCWD 16
#define SYS_FUTEX 17
#define SYS_PIPE 18
#define SYS_SYSCONF 19
#define SYS_SCHED_SETAFFINITY 20
#define SYS_SCHED_GETAFFINITY 21
#define SYS_SCHED_SETATTR 22
#define SYS_SCHED_GETATTR 23
#define SYS_SET_ROBUST_LIST 24
#define SYS_GET_ROBUST_LIST 25

/* PSE51 clock and nanosleep (item 15) */
#define SYS_CLOCK_GETTIME 26
#define SYS_CLOCK_GETRES 27
#define SYS_NANOSLEEP 28

/* PSE51 memory locking -- no-ops on bare metal (item 15e) */
#define SYS_MLOCKALL 29
#define SYS_MUNLOCKALL 30

/* PSE51 synchronization syscalls (item 15a) */
#define SYS_MUTEX_INIT 31
#define SYS_MUTEX_LOCK 32
#define SYS_MUTEX_TRYLOCK 33
#define SYS_MUTEX_UNLOCK 34
#define SYS_COND_INIT 35
#define SYS_COND_WAIT 36
#define SYS_COND_TIMEDWAIT 37
#define SYS_COND_SIGNAL 38
#define SYS_COND_BROADCAST 39
#define SYS_SEM_INIT 40
#define SYS_SEM_WAIT 41
#define SYS_SEM_TRYWAIT 42
#define SYS_SEM_POST 43
#define SYS_SEM_TIMEDWAIT 44

/* PSE51 scheduling syscalls (item 17) */
#define SYS_SCHED_GET_PRIORITY_MIN 45
#define SYS_SCHED_GET_PRIORITY_MAX 46
#define SYS_SCHED_YIELD 47
#define SYS_SCHED_SETPARAM 48
#define SYS_SCHED_GETPARAM 49

/* POSIX barriers (item 15i) */
#define SYS_BARRIER_INIT 50
#define SYS_BARRIER_WAIT 51
#define SYS_BARRIER_DESTROY 52

/* POSIX rwlocks (item 15j) */
#define SYS_RWLOCK_INIT 53
#define SYS_RWLOCK_RDLOCK 54
#define SYS_RWLOCK_WRLOCK 55
#define SYS_RWLOCK_TRYRDLOCK 56
#define SYS_RWLOCK_TRYWRLOCK 57
#define SYS_RWLOCK_UNLOCK 58
#define SYS_RWLOCK_TIMEDRDLOCK 59
#define SYS_RWLOCK_TIMEDWRLOCK 60
#define SYS_RWLOCK_DESTROY 61

/* POSIX message queues (item 15b) */
#define SYS_MQ_OPEN 62
#define SYS_MQ_CLOSE 63
#define SYS_MQ_SEND 64
#define SYS_MQ_RECEIVE 65
#define SYS_MQ_TIMEDRECEIVE 66

/* PSE51 thread management (item 15d) */
#define SYS_THREAD_CREATE 67
#define SYS_THREAD_JOIN 68
#define SYS_THREAD_DETACH 69
#define SYS_THREAD_EXIT 70
#define SYS_THREAD_SELF 71

/* Signals (item 16) */
#define SYS_KILL 72
#define SYS_SIGACTION 73
#define SYS_SIGRETURN 74

/* PSE51 interval timers (item 15f) */
#define SYS_TIMER_CREATE 75
#define SYS_TIMER_SETTIME 76
#define SYS_TIMER_DELETE 77
#define SYS_TIMER_GETTIME 78
#define SYS_TIMER_GETOVERRUN 79

/* PSE51 range memory locking. mlock / munlock are required by PSE51
 * even when memory is permanently resident; ship them as no-op
 * success after argument validation, mirroring mlockall / munlockall.
 */
#define SYS_MLOCK 80
#define SYS_MUNLOCK 81

/* Synchronized I/O. PSE51 mandates _POSIX_FSYNC. The disk-backed SFS
 * already commits writes synchronously internally; the user-visible
 * syscalls validate their FD and return success.
 */
#define SYS_FSYNC 82
#define SYS_FDATASYNC 83

/* Single-threaded sigprocmask. Modify-and-return-old of the
 * per-process blocked mask. Independent of the per-thread state
 * migration: today the blocked mask lives on struct proc and is
 * shared by the (single) thread; once pthread support lands, this
 * syscall must be re-shaped to a per-thread pthread_sigmask.
 */
#define SYS_SIGPROCMASK 84

/* Per-thread scheduling parameters
 * (pthread_{setschedparam,pthread_getschedparam}). Take a CAP_TYPE_THREAD
 * handle (0 = self) and a scalar priority. SYS_SCHED_{SETPARAM,GETPARAM}
 * continue to operate on the calling thread only; these add the by-handle form.
 */
#define SYS_THREAD_SETSCHEDPARAM 85
#define SYS_THREAD_GETSCHEDPARAM 86

/* POSIX scheduler-policy accessors (sched_{setscheduler,getscheduler}). Mazu
 * honors SCHED_FIFO semantics for all normal threads; SCHED_OTHER and SCHED_RR
 * are accepted but coerced to FIFO. SCHED_DEADLINE is rejected here because it
 * has its own ABI via SYS_SCHED_SETATTR.
 */
#define SYS_SCHED_SETSCHEDULER 87
#define SYS_SCHED_GETSCHEDULER 88

/* PSE51 thread-directed signal API.
 *
 * SYS_PTHREAD_KILL: deliver signo directly to the thread named by the given
 * CAP_TYPE_THREAD handle inside the calling proc. Different from SYS_KILL which
 * is process-directed.
 *
 * SYS_PTHREAD_SIGMASK: identical wire shape to SYS_SIGPROCMASK (operates on the
 * calling thread's td_sig.blocked) but exposes the pthread_sigmask name for ABI
 * clarity.
 * Userspace libc maps pthread_sigmask -> this; sigprocmask -> SYS_SIGPROCMASK.
 */
#define SYS_PTHREAD_KILL 89
#define SYS_PTHREAD_SIGMASK 90

/* PSE51 wait-for-signal variants. sigsuspend replaces the calling thread's
 * blocked mask with the supplied set, blocks until any signal arrives that is
 * not in the new mask, then restores the old mask. sigtimedwait blocks until
 * a signal in the supplied set becomes pending or the timeout expires, then
 * dequeues the signal (without invoking its handler) and returns its number.
 * sigwait is the no-timeout variant, expressed by passing a NULL timeout.
 */
#define SYS_SIGSUSPEND 91
#define SYS_SIGTIMEDWAIT 92

/* PSE51 thread cancellation
 * (pthread_{cancel,setcancelstate,setcanceltype,testcancel}). Cancellation is
 * deferred: a thread observes the pending bit at the next cancellation point
 * (any blocking syscall checks signal_pending_current / thread_cancel_pending
 * before entering the wait) and exits with code -ECANCELED.
 */
#define SYS_THREAD_CANCEL 93
#define SYS_THREAD_SETCANCELSTATE 94
#define SYS_THREAD_TESTCANCEL 95

/* Capability management. */
#define SYS_CAP_DROP 96
#define SYS_CAP_TRANSFER 97
#define SYS_CAP_REVOKE_DELEGATE 98
#define SYS_CAP_GET_TOKEN 99

#define SYS_NR 100 /* total number of syscalls */

/* pthread_setcancelstate state values. */
#define PTHREAD_CANCEL_ENABLE 0
#define PTHREAD_CANCEL_DISABLE 1

/* POSIX scheduling policies (subset). SCHED_FIFO is the only policy Mazu honors
 * directly; SCHED_OTHER and SCHED_RR map onto it.
 */
#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2

#ifndef __ASSEMBLER__

#include <isr.h>

struct sched_task;

/* Per-syscall policy flags.  Checked by the authorization gate in
 * syscall_dispatch() before the handler is invoked.
 */
#define SYSCALL_F_NEEDS_PROC BIT(0) /* requires td->proc != NULL */
#define SYSCALL_F_WRITE_FS BIT(1)   /* reserved: not yet enforced */

/* Dispatch a syscall from an ecall-from-U-mode trap.
 * tf->a7 = syscall number, tf->a0-a5 = arguments.
 * Returns the value to place in a0 (or negative error).
 */
i64 syscall_dispatch(struct trap_frame *tf, struct sched_task *td);

/* Security counters, read by /api/stats. */
struct syscall_security_stats {
    u64 nr_denied; /* total syscalls blocked by policy */
    u64 nr_enosys; /* invalid syscall numbers */
};
struct syscall_security_stats syscall_security_stats_get(void);

#endif /* __ASSEMBLER__ */

#endif /* MAZU_SYSCALL_H */
