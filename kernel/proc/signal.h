/* SPDX-License-Identifier: MIT */
/* Signal infrastructure for PSE51.
 *
 * Signal types and state struct are defined in <mazu/proc.h>.
 * This header provides the signal API functions.
 */

#ifndef MAZU_SIGNAL_H
#define MAZU_SIGNAL_H

#include <isr.h>
#include <mazu/errordef.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/uaccess.h>

/* Signal numbers (POSIX subset). */
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGABRT 6
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGCHLD 17

/* Signal disposition values. */
#define SIG_DFL ((sig_handler_fn_t) 0)
#define SIG_IGN ((sig_handler_fn_t) 1)

/* sigprocmask(2) how arguments. */
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

static inline u32 sig_bit(i32 signo)
{
    return 1U << signo;
}

/* Initialize per-process signal state for a new process. The
 * per-thread fields (pending/blocked/frame_*) live in struct
 * sched_task::td_sig and are zeroed at task creation, not here.
 */
void signal_init(struct signal_state *ss);

/* Enqueue a signal to a process. Process-directed delivery records the
 * bit in proc_pending and picks one thread only as a wakeup hint.
 * Returns 0 or -errno.
 */
i32 signal_send(struct proc *p, i32 signo);

/* Enqueue a process-directed signal with a queued payload value.
 * Repeated deliveries of the same signo are preserved up to the
 * bounded per-signal queue depth. Returns -EAGAIN if that queue is
 * full.
 */
i32 signal_queue_send(struct proc *p, i32 signo, u64 value);

/* Claim one process-directed pending instance of signo. Caller must
 * hold p->sig_lock. Queued sigqueue payloads are preferred (FIFO); when
 * one is dequeued, *out_value receives the payload and *out_has_value is
 * set true. When no payload is queued but a plain kill-style instance is
 * pending, that instance is consumed and *out_has_value is set false.
 * The summary proc_pending bit is updated to reflect any remaining source.
 * Returns false if no instance of signo is pending.
 */
bool signal_claim_proc_pending_locked(struct proc *p,
                                      i32 signo,
                                      u64 *out_value,
                                      bool *out_has_value);

/* Re-insert a previously-claimed process-directed instance after a partial
 * delivery failure (e.g. sigtimedwait copy_to_user fault after the signal
 * was already dequeued). Caller must hold p->sig_lock. If had_value is true,
 * the payload is pushed back at the queue head; if the queue is now full
 * (because a concurrent sigqueue arrived after the original pop), the
 * payload is dropped and a plain pending instance is recorded instead so the
 * signal itself stays observable. If had_value is false, a plain pending
 * instance is restored. The summary proc_pending bit is refreshed.
 * Returns true if a payload had to be dropped because the queue was full.
 */
bool signal_restore_proc_pending_locked(struct proc *p,
                                        i32 signo,
                                        u64 value,
                                        bool had_value);

/* Return true if this specific thread can take signo immediately. */
static inline bool signal_thread_can_deliver(const struct sched_task *td,
                                             i32 signo)
{
    return td && signo > 0 && signo < SIG_MAX &&
           (__atomic_load_n(&td->td_sig.blocked, __ATOMIC_RELAXED) &
            sig_bit(signo)) == 0;
}

/* Check and deliver pending signals to the given thread on
 * return-to-user.  Modifies the trap frame to divert to the
 * handler.  Returns true if a signal was delivered.
 */
bool signal_deliver(struct sched_task *td, struct trap_frame *tf);

/* Restore trap frame after signal handler returns (SYS_SIGRETURN). */
i32 signal_return(struct sched_task *td, struct trap_frame *tf);

/* Handle a faulting return through the synthetic sigreturn trampoline. */
bool signal_handle_trampoline_fault(struct sched_task *td,
                                    struct trap_frame *tf);

/* Per-process synthetic sigreturn return address.
 * This uses the existing unmapped guard page below the user stack.
 */
static inline ptr signal_trampoline_pc(struct proc *p)
{
    if (!p)
        return (ptr) 0;
    return (ptr) (p->va_stack_top - USER_STACK_SIZE - PAGE_SIZE);
}

/* Per-process synthetic thread-exit return address. A user thread that
 * returns from its entry function pops this address into pc; the
 * unmapped page faults and the trap handler recognizes the PC and
 * issues SYS_THREAD_EXIT(0). Distinct from signal_trampoline_pc by
 * the size of one instruction so they share the same guard page.
 */
static inline ptr thread_exit_trampoline_pc(struct proc *p)
{
    if (!p)
        return (ptr) 0;
    return (ptr) (signal_trampoline_pc(p) + 4);
}

/* Magic preloaded in callee-saved s11 at thread creation. The
 * trampoline detection in trap.c checks both the PC and this magic
 * before synthesizing SYS_THREAD_EXIT, so a stray wild-pointer jump
 * to the trampoline PC (e.g. from a corrupted ra) does not silently
 * succeed; it falls through to the normal user-fault path and
 * produces a diagnostic dump. ASCII for "thrx".
 */
#define THREAD_EXIT_TRAMPOLINE_MAGIC 0x7468727800000000ULL

/* Lockless best-effort check for deliverable signals on a specific
 * thread. Used to skip the full signal-delivery lock path on the
 * common no-signal return-to-user fast path. Reads use atomics
 * because writers (signal_send / sigprocmask) hold sig_lock but
 * this read is unlocked. Folds the per-proc pending mask so a
 * process-directed signal that landed on a different thread is
 * still observed when this thread reaches return-to-user.
 */
static inline bool signal_has_deliverable(struct sched_task *td)
{
    if (!td)
        return false;
    u32 pending = __atomic_load_n(&td->td_sig.pending, __ATOMIC_RELAXED);
    u32 blocked = __atomic_load_n(&td->td_sig.blocked, __ATOMIC_RELAXED);
    if (td->proc) {
        u32 proc_pending = __atomic_load_n(&td->proc->sig_state.proc_pending,
                                           __ATOMIC_RELAXED);
        pending |= proc_pending;
    }
    return (pending & ~blocked) != 0;
}

/* Return true when trap exit needs to run signal_deliver even if no
 * signal is currently deliverable. sigsuspend uses this to restore
 * its saved mask on a wakeup where another thread consumed the shared
 * pending bit before this thread reached return-to-user.
 */
static inline bool signal_needs_trap_exit(struct sched_task *td)
{
    return td &&
           (signal_has_deliverable(td) ||
            __atomic_load_n(&td->td_sig.sigsuspend_active, __ATOMIC_RELAXED));
}

/* Return true when deferred pthread cancellation should fire for td.
 * Lockless because the state is a pair of per-task booleans written by
 * syscall code and consumed only as a best-effort cancellation-point poll.
 */
static inline bool thread_cancel_enabled_pending(const struct sched_task *td)
{
    return td && td->proc &&
           __atomic_load_n(&td->td_cancel_pending, __ATOMIC_RELAXED) &&
           !__atomic_load_n(&td->td_cancel_disabled, __ATOMIC_RELAXED);
}

/* Return true if the current task has deliverable signals.
 * Safe to call from any context; returns false for kernel tasks.
 */
static inline bool signal_pending_current(void)
{
    struct sched_task *td = sched_current_task();
    return td && td->proc && signal_has_deliverable(td);
}

/* Return the errno a blocking cancellation point should report.
 * Deferred cancellation outranks EINTR: a canceled thread must unwind
 * through pthread_exit rather than resume user-space retry logic.
 */
static inline i32 wait_abort_error_current(void)
{
    struct sched_task *td = sched_current_task();

    if (thread_cancel_enabled_pending(td))
        return -(i32) ECANCELED;
    if (td && td->proc && signal_has_deliverable(td))
        return -(i32) EINTR;
    return 0;
}

#endif /* MAZU_SIGNAL_H */
