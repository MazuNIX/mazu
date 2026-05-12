/* SPDX-License-Identifier: MIT */
/* Signal delivery for PSE51.
 *
 * Signal delivery model:
 * - Plain kill-style signals are pending bits.
 * - sigqueue-style process-directed payloads use a bounded per-signo queue.
 * - Delivery happens on trap exit (return-to-user path).
 * - Handler invocation: save current trap frame on the user stack,
 *   set up execution to jump to the handler, sys_sigreturn restores.
 * - SIGKILL and SIGTERM with default disposition terminate the process.
 */

#include "signal.h"
#include <mazu/asm.h>
#include <mazu/assert.h>
#include <mazu/eventlog.h>
#include <mazu/print.h>
#include <mazu/sched.h>
#include <mazu/uaccess.h>

#define SIGNAL_FRAME_MAGIC 0x53494746U

void signal_init(struct signal_state *ss)
{
    /* Per-task signal state (pending/blocked/frame_*) is zeroed at
     * task creation in sched_create_user_task; this initializer is
     * for the per-process disposition table only.
     */
    ss->proc_pending = 0;
    ss->proc_pending_plain = 0;
    for (i32 i = 0; i < SIG_MAX; i++) {
        ss->actions[i].handler = SIG_DFL;
        ss->actions[i].sa_mask = 0;
        ss->actions[i].sa_flags = 0;
        ss->queued[i].head = 0;
        ss->queued[i].tail = 0;
        ss->queued[i].count = 0;
    }
}

static inline bool sig_valid(i32 signo)
{
    return signo > 0 && signo < SIG_MAX;
}

static bool signal_value_queue_push_locked(struct signal_state *ss,
                                           i32 signo,
                                           u64 value)
{
    struct signal_value_queue *q = &ss->queued[signo];

    /* Producers cap at the user-visible limit; the +1 internal slot is
     * reserved for the rollback-after-fault path below.
     */
    if (q->count >= SIGQUEUE_MAX_PER_SIGNO)
        return false;
    q->values[q->tail] = value;
    q->tail = (u8) ((q->tail + 1) % SIGQUEUE_RING_CAP);
    q->count++;
    return true;
}

static bool signal_value_queue_pop_locked(struct signal_state *ss,
                                          i32 signo,
                                          u64 *out_value)
{
    struct signal_value_queue *q = &ss->queued[signo];

    if (q->count == 0)
        return false;
    if (out_value)
        *out_value = q->values[q->head];
    q->head = (u8) ((q->head + 1) % SIGQUEUE_RING_CAP);
    q->count--;
    return true;
}

/* Push a payload back at the queue head (LIFO insert used only to undo a
 * previous pop). Always succeeds for a single in-flight consumer because the
 * ring is sized SIGQUEUE_MAX_PER_SIGNO + 1 (the producer cap leaves one slot
 * unused for exactly this case). Returns false only on the pathological case
 * where multiple consumers race their rollbacks past the reserved slot.
 */
static bool signal_value_queue_push_head_locked(struct signal_state *ss,
                                                i32 signo,
                                                u64 value)
{
    struct signal_value_queue *q = &ss->queued[signo];

    if (q->count >= SIGQUEUE_RING_CAP)
        return false;
    q->head = (u8) ((q->head + SIGQUEUE_RING_CAP - 1) % SIGQUEUE_RING_CAP);
    q->values[q->head] = value;
    q->count++;
    return true;
}

/* Refresh the summary proc_pending bit for signo from the underlying state.
 * Caller must hold p->sig_lock. The atomic ensures the lockless fast-path
 * reader (signal_has_deliverable) sees a coherent value.
 */
static inline void sig_refresh_proc_pending_locked(struct signal_state *ss,
                                                   i32 signo)
{
    bool any = (ss->proc_pending_plain & sig_bit(signo)) ||
               ss->queued[signo].count > 0;
    if (any)
        __atomic_or_fetch(&ss->proc_pending, sig_bit(signo), __ATOMIC_RELAXED);
    else
        __atomic_and_fetch(&ss->proc_pending, ~sig_bit(signo),
                           __ATOMIC_RELAXED);
}

static inline bool signal_restore_tf_valid(struct proc *p,
                                           const struct trap_frame *tf)
{
    if (!p || !tf)
        return false;
    if ((tf->sstatus & (SSTATUS_SPP | SSTATUS_SUM)) != 0)
        return false;
    if (!proc_vma_check_access(p, (ptr) tf->sepc, 1, VMA_PERM_EXEC))
        return false;
    if (!proc_vma_check_access(p, (ptr) tf->sp, 1, VMA_PERM_WRITE))
        return false;
    return true;
}

static inline void signal_restore_tf(struct trap_frame *dst,
                                     const struct trap_frame *src)
{
    *dst = *src;
    dst->scause = 0;
    dst->stval = 0;
    dst->sstatus = SSTATUS_SPIE;
}

/* Interrupt a task that is blocked in a wait state so it can observe
 * a newly posted signal at the earliest opportunity.
 *
 * TD_STATE_SLEEPING (nanosleep): sched_wake_sleeping cancels the sleep
 * callout, removes from sleep_list, and enqueues as READY, all under
 * sched_lock, which serializes against the normal sleep callout wake.
 *
 * TD_STATE_BLOCKED / TD_STATE_SEM_WAIT (sync primitives): we cannot
 * safely call sched_wake_ready because the normal wake path (sem_post,
 * condvar_signal, etc.) may concurrently wake and enqueue the same task,
 * causing double-enqueue corruption.  Instead, the pending-signal bit
 * is already set in sig_state.pending, and every interruptible wait loop
 * checks signal_pending_current() at its next iteration.  For timed waits
 * the callout will fire and re-enter the loop.  For untimed waits the
 * signal is delivered when the primitive's normal wake path fires (post,
 * signal, broadcast, unlock).  SIGKILL bypasses this entirely via the
 * dedicated proc_exit + TD_STATE_TERMINATING path.
 */
static void signal_interrupt_task(struct sched_task *td)
{
    if (!td)
        return;

    if (td->state == TD_STATE_SLEEPING)
        sched_wake_sleeping(td);
}

/* True if this thread is alive enough to receive a signal: attached
 * to its proc, not in a dying join state, and not already terminating
 * for unrelated reasons.
 */
static bool signal_thread_is_alive(const struct sched_task *td)
{
    if (!td)
        return false;
    if (td->td_join_state == TD_JOIN_EXITED ||
        td->td_join_state == TD_JOIN_REAPED)
        return false;
    if (td->state == TD_STATE_TERMINATING)
        return false;
    return true;
}

static bool signal_thread_waits_for_signo(const struct sched_task *td,
                                          i32 signo)
{
    return td && signo > 0 && signo < SIG_MAX &&
           (__atomic_load_n(&td->td_sig.sigwait_set, __ATOMIC_RELAXED) &
            sig_bit(signo)) != 0;
}

/* Pick a thread to nudge (wake / interrupt) so a process-directed
 * signal is observed promptly. Used purely as a wakeup hint; the bit
 * itself lives on proc->sig_state.proc_pending and is observable by
 * any thread when it returns to user space. Returns NULL if no live
 * thread is found.
 */
static struct sched_task *signal_pick_wake_target_locked(struct proc *p,
                                                         i32 signo)
{
    if (!p)
        return NULL;
    bool unmaskable = (signo == SIGKILL);
    struct sched_task *leader = proc_thread_group_leader(p);
    if (!unmaskable && signal_thread_is_alive(leader) &&
        signal_thread_waits_for_signo(leader, signo))
        return leader;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        struct sched_task *td = p->tasks[i];
        if (td == leader || !signal_thread_is_alive(td))
            continue;
        if (signal_thread_waits_for_signo(td, signo))
            return td;
    }
    if (signal_thread_is_alive(leader) &&
        (unmaskable || signal_thread_can_deliver(leader, signo)))
        return leader;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        struct sched_task *td = p->tasks[i];
        if (td == leader || !signal_thread_is_alive(td))
            continue;
        if (unmaskable || signal_thread_can_deliver(td, signo))
            return td;
    }
    return signal_thread_is_alive(leader) ? leader : NULL;
}

i32 signal_send(struct proc *p, i32 signo)
{
    if (!p || !sig_valid(signo))
        return -(i32) EINVAL;

    /* Process-directed: write the bit into the per-proc pending mask
     * (not into any single thread's td_sig.pending). At return-to-user
     * each thread folds proc_pending into its delivery view, so the
     * signal survives the picked thread exiting before delivery.
     *
     * The picked target here is just for the wakeup hint -- if it has
     * exited by the time anyone returns to user space, some other
     * live thread will still observe the bit via signal_has_deliverable.
     */
    bool need_kill = false;
    bool delivered = false;

    u64 tflags = proc_table_lock_irqsave();
    if (p->state != PROC_STATE_FREE && p->state != PROC_STATE_ZOMBIE) {
        u64 sflags = proc_sig_lock_irqsave(p);
        p->sig_state.proc_pending_plain |= sig_bit(signo);
        sig_refresh_proc_pending_locked(&p->sig_state, signo);
        proc_sig_unlock_irqrestore(p, sflags);
        delivered = true;
        if (signo == SIGKILL)
            need_kill = true;
        else
            signal_interrupt_task(signal_pick_wake_target_locked(p, signo));
    }
    proc_table_unlock_irqrestore(tflags);

    if (!delivered)
        return 0;

    if (need_kill) {
        /* proc_exit is idempotent: it checks state under its own
         * proc_table_lock and bails if the proc is already exiting.
         */
        proc_exit(p, -SIGKILL);
        return 0;
    }
    return 0;
}

i32 signal_queue_send(struct proc *p, i32 signo, u64 value)
{
    if (!p || !sig_valid(signo))
        return -(i32) EINVAL;

    bool need_kill = false;
    bool delivered = false;
    i32 rc = 0;

    u64 tflags = proc_table_lock_irqsave();
    if (p->state != PROC_STATE_FREE && p->state != PROC_STATE_ZOMBIE) {
        u64 sflags = proc_sig_lock_irqsave(p);
        if (!signal_value_queue_push_locked(&p->sig_state, signo, value))
            rc = -(i32) EAGAIN;
        else {
            sig_refresh_proc_pending_locked(&p->sig_state, signo);
            delivered = true;
            if (signo == SIGKILL)
                need_kill = true;
            else
                signal_interrupt_task(signal_pick_wake_target_locked(p, signo));
        }
        proc_sig_unlock_irqrestore(p, sflags);
    }
    proc_table_unlock_irqrestore(tflags);

    if (rc < 0)
        return rc;
    if (!delivered)
        return 0;

    if (need_kill) {
        proc_exit(p, -SIGKILL);
        return 0;
    }
    return 0;
}

bool signal_claim_proc_pending_locked(struct proc *p,
                                      i32 signo,
                                      u64 *out_value,
                                      bool *out_has_value)
{
    if (!p || !sig_valid(signo) ||
        (p->sig_state.proc_pending & sig_bit(signo)) == 0)
        return false;

    /* Prefer a queued sigqueue payload (FIFO). If none is queued but a plain
     * kill-style instance is still pending, consume that instead. Each call
     * consumes exactly one source so kill() and sigqueue() of the same signo
     * can coexist without one silently swallowing the other.
     */
    bool had_value =
        signal_value_queue_pop_locked(&p->sig_state, signo, out_value);
    if (!had_value && (p->sig_state.proc_pending_plain & sig_bit(signo))) {
        p->sig_state.proc_pending_plain &= ~sig_bit(signo);
    }
    if (out_has_value)
        *out_has_value = had_value;

    sig_refresh_proc_pending_locked(&p->sig_state, signo);
    return true;
}

bool signal_restore_proc_pending_locked(struct proc *p,
                                        i32 signo,
                                        u64 value,
                                        bool had_value)
{
    if (!p || !sig_valid(signo))
        return false;

    bool payload_dropped = false;
    if (had_value) {
        if (!signal_value_queue_push_head_locked(&p->sig_state, signo, value)) {
            /* Queue filled up via a concurrent sigqueue after the pop. The
             * exact payload is lost, but a same-signo instance is still in
             * flight via the queue, so observability of the signal is not
             * lost. Surface a plain pending instance as well so the receiver
             * is guaranteed to retry.
             */
            p->sig_state.proc_pending_plain |= sig_bit(signo);
            payload_dropped = true;
        }
    } else {
        p->sig_state.proc_pending_plain |= sig_bit(signo);
    }
    sig_refresh_proc_pending_locked(&p->sig_state, signo);
    return payload_dropped;
}

/* Saved signal context pushed onto the user stack. */
struct signal_frame {
    u32 magic;
    u32 cookie;
    struct trap_frame saved_tf;
    u32 saved_blocked;
    ptr prev_frame;
    u32 prev_cookie;
    i32 signo;
};

bool signal_deliver(struct sched_task *td, struct trap_frame *tf)
{
    if (!td)
        return false;
    /* Snapshot td->proc under proc_table_lock so a concurrent
     * proc_exit on another hart cannot detach the back-pointer
     * mid-function. After the snapshot, the proc memory itself is
     * stable (proc_table[] is statically allocated; only state and
     * magic transition). Bail if magic was poisoned by proc_free.
     */
    struct proc *p;
    {
        u64 tflags = proc_table_lock_irqsave();
        p = td->proc;
        proc_table_unlock_irqrestore(tflags);
    }
    if (!p || p->magic != PROC_MAGIC)
        return false;

    u64 flags = proc_sig_lock_irqsave(p);
    /* Fold the per-proc pending mask into this thread's delivery
     * view so a process-directed signal whose original wake target
     * has since exited still gets observed by a surviving thread.
     */
    u32 thread_pending = td->td_sig.pending;
    u32 proc_pending = p->sig_state.proc_pending;
    u32 deliverable = (thread_pending | proc_pending) & ~td->td_sig.blocked;
    if (deliverable == 0) {
        if (td->td_sig.sigsuspend_active) {
            td->td_sig.blocked = td->td_sig.sigsuspend_saved_blocked;
            td->td_sig.sigsuspend_active = false;
        }
        proc_sig_unlock_irqrestore(p, flags);
        return false;
    }

    /* Find lowest-numbered pending unblocked signal. */
    i32 signo = 0;
    for (i32 i = 1; i < SIG_MAX; i++) {
        if (deliverable & sig_bit(i)) {
            signo = i;
            break;
        }
    }
    if (signo == 0) {
        proc_sig_unlock_irqrestore(p, flags);
        return false;
    }

    /* Claim the bit. Prefer to take it off the per-thread mask if it was set
     * there (so a thread-directed delivery does not also clear the process-wide
     * bit and starve other threads); otherwise clear it from proc_pending. The
     * two masks may both have the bit if a sender wrote proc_pending and a
     * thread later self-targeted.
     */
    if (thread_pending & sig_bit(signo))
        td->td_sig.pending &= ~sig_bit(signo);
    else
        (void) signal_claim_proc_pending_locked(p, signo, NULL, NULL);
    sig_handler_fn_t handler = p->sig_state.actions[signo].handler;

    if (handler == SIG_IGN) {
        /* Restore the pre-sigsuspend mask if this thread was parked in
         * sigsuspend: the signal was dequeued but no handler ran, and POSIX
         * requires the original mask to be effective when sigsuspend returns
         * -EINTR. Doing this under sig_lock keeps the lockless reader
         *  (signal_has_deliverable) consistent.
         */
        if (td->td_sig.sigsuspend_active) {
            td->td_sig.blocked = td->td_sig.sigsuspend_saved_blocked;
            td->td_sig.sigsuspend_active = false;
        }
        proc_sig_unlock_irqrestore(p, flags);
        return false;
    }

    if (handler == SIG_DFL) {
        proc_sig_unlock_irqrestore(p, flags);
        /* Default: terminate (except SIGCHLD which is ignored). */
        if (signo == SIGCHLD)
            return false;
        pr_info(STR("signal: pid=%hu terminated by signal %d\n"), p->pid,
                signo);
        proc_exit(p, -signo);
        sched_set_task_state(td, TD_STATE_TERMINATING);
        return true;
    }

    /* Custom handler: push signal frame onto user stack.
     *
     * If the thread is in sigsuspend, the frame.saved_blocked snapshot must
     * capture the ORIGINAL pre-suspend mask, not the temporary suspend mask.
     * sigreturn restores from frame.saved_blocked, so this is what makes
     * sigsuspend POSIX-correct: the handler runs with sa_mask + signo blocked
     * on top of the suspend mask, and after sigreturn the original mask is back
     * in effect.
     */
    u64 sp = tf->sp;
    sp -= sizeof(struct signal_frame);
    sp &= ~0xFUL;

    u32 frame_saved_blocked = td->td_sig.sigsuspend_active
                                  ? td->td_sig.sigsuspend_saved_blocked
                                  : td->td_sig.blocked;
    struct signal_frame frame = {
        .magic = SIGNAL_FRAME_MAGIC,
        .cookie = td->td_sig.frame_cookie + 1,
        .saved_tf = *tf,
        .saved_blocked = frame_saved_blocked,
        .prev_frame = td->td_sig.frame_top,
        .prev_cookie = td->td_sig.frame_cookie,
        .signo = signo,
    };
    if (td->td_sig.sigsuspend_active)
        td->td_sig.sigsuspend_active = false;

    td->td_sig.blocked |= p->sig_state.actions[signo].sa_mask | sig_bit(signo);
    td->td_sig.frame_prev = frame.prev_frame;
    td->td_sig.frame_prev_cookie = frame.prev_cookie;
    td->td_sig.frame_top = (ptr) sp;
    td->td_sig.frame_cookie = frame.cookie;
    proc_sig_unlock_irqrestore(p, flags);

    i64 rc = copy_to_user((ptr) sp, &frame, sizeof(frame));
    if (rc < 0) {
        pr_info(STR("signal: pid=%hu stack fault during signal %d\n"), p->pid,
                signo);
        proc_exit(p, -signo);
        sched_set_task_state(td, TD_STATE_TERMINATING);
        return true;
    }

    /* Redirect to handler: a0=signo, a1=frame_ptr, sp=new stack. */
    tf->sepc = (u64) (uptr) handler;
    tf->a0 = (u64) signo;
    tf->a1 = (u64) sp;
    tf->sp = sp;
    tf->ra = (u64) signal_trampoline_pc(p);

    return true;
}

i32 signal_return(struct sched_task *td, struct trap_frame *tf)
{
    if (!td)
        return -(i32) EPERM;
    struct proc *p;
    {
        u64 tflags = proc_table_lock_irqsave();
        p = td->proc;
        proc_table_unlock_irqrestore(tflags);
    }
    if (!p || p->magic != PROC_MAGIC)
        return -(i32) EPERM;

    ptr frame_ptr = (ptr) tf->a0;
    struct signal_frame frame;
    i64 rc = copy_from_user(&frame, frame_ptr, sizeof(frame));
    if (rc < 0)
        return -(i32) EFAULT;

    /* Validate the saved trap frame BEFORE committing any signal state changes.
     * A malicious handler could supply a frame with valid magic/cookie but an
     * invalid saved_tf; committing first would corrupt the frame stack and
     * signal mask.
     */
    if (!signal_restore_tf_valid(p, &frame.saved_tf))
        return -(i32) EPERM;

    u64 flags = proc_sig_lock_irqsave(p);
    bool frame_ok = frame.magic == SIGNAL_FRAME_MAGIC &&
                    frame_ptr == td->td_sig.frame_top &&
                    frame.cookie == td->td_sig.frame_cookie;
    if (!frame_ok) {
        proc_sig_unlock_irqrestore(p, flags);
        return -(i32) EPERM;
    }
    td->td_sig.frame_top = frame.prev_frame;
    td->td_sig.frame_cookie = frame.prev_cookie;
    td->td_sig.frame_prev = (ptr) 0;
    td->td_sig.frame_prev_cookie = 0;
    td->td_sig.blocked = frame.saved_blocked;
    proc_sig_unlock_irqrestore(p, flags);

    signal_restore_tf(tf, &frame.saved_tf);
    return 0;
}

bool signal_handle_trampoline_fault(struct sched_task *td,
                                    struct trap_frame *tf)
{
    if (!td || !tf)
        return false;
    struct proc *p;
    {
        u64 tflags = proc_table_lock_irqsave();
        p = td->proc;
        proc_table_unlock_irqrestore(tflags);
    }
    /* Defensive magic check: if proc_free poisoned the slot between the
     * unlock and this read, va_stack_top inside signal_trampoline_pc would
     * be stale.  Matches the guards in signal_deliver / signal_return.
     */
    if (!p || p->magic != PROC_MAGIC ||
        tf->sepc != (u64) signal_trampoline_pc(p))
        return false;

    tf->a0 = tf->sp;
    return signal_return(td, tf) == 0;
}
