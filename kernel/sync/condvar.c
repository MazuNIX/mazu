/* SPDX-License-Identifier: MIT */
/* Condition variable implementation.
 *
 * Built on top of wait queues.  condvar_wait releases the associated
 * pi_mutex AFTER adding the caller to the wait queue, preventing the
 * classic lost-wakeup race (signal between unlock and sleep).
 *
 * Timed wait arms a callout that wakes the specific waiter on expiry.
 * The callout callback runs in ISR context and acquires wq.lock (valid
 * because callout_process drops the callout list lock before callbacks).
 */

#include "condvar.h"
#include <mazu/callout.h>
#include <mazu/eventlog.h>
#include <mazu/ipi.h>
#include <mazu/sched.h>
#include <mazu/spinlock.h>
#include <mazu/time.h>
#include "../lockdep.h"
#include "../proc/signal.h"

void condvar_init(struct condvar *cv)
{
    init_waitqueue_head(&cv->wq);
}

i32 condvar_wait(struct condvar *cv, struct pi_mutex *mtx)
{
    DEBUG_ASSERT(!in_interrupt_context());

    struct wait_queue_entry wqe = {
        .task = sched_current_task(),
        .reason = WAIT_UNBLOCK_NONE,
    };
    list_init(&wqe.node);

    /* Add to wait queue BEFORE releasing the mutex.  The wq.lock
     * serializes with condvar_signal, preventing lost wakeups.
     */
    prepare_to_wait(&cv->wq, &wqe);
    pi_mutex_unlock(mtx);

    sched_yield_trap();

    finish_wait(&cv->wq, &wqe);
    pi_mutex_lock(mtx);
    if (wqe.reason == WAIT_UNBLOCK_DESTROY) {
        i32 abort = wait_abort_error_current();
        if (abort < 0)
            return abort;
    }
    return 0;
}

static void condvar_timeout_fn(void *arg)
{
    struct wait_queue_entry *wqe = arg;
    if (!wqe->cleanup_wq || wqe->cleanup_self != wqe)
        return;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&wqe->cleanup_wq->lock);

    /* Only wake the task if it is still blocked and no terminal reason has
     * been recorded.  A killed task (TD_STATE_TERMINATING) must not be
     * revived — the kill path owns its state transition.
     */
    if (!wqe->task || wait_should_exit(wqe->reason) ||
        wqe->task->state != TD_STATE_BLOCKED) {
        spin_unlock_irqrestore(&wqe->cleanup_wq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return;
    }

    /* Wake with TIMEOUT reason. */
    wqe->reason = WAIT_UNBLOCK_TIMEOUT;
    sched_wake_ready(wqe->task);

    spin_unlock_irqrestore(&wqe->cleanup_wq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
}

i32 condvar_wait_timeout(struct condvar *cv,
                         struct pi_mutex *mtx,
                         struct time_ms timeout)
{
    DEBUG_ASSERT(!in_interrupt_context());

    struct wait_queue_entry wqe = {
        .task = sched_current_task(),
        .reason = WAIT_UNBLOCK_NONE,
    };
    list_init(&wqe.node);

    struct callout tmo;
    callout_init(&tmo);
    wqe.timeout_callout = &tmo;

    prepare_to_wait(&cv->wq, &wqe);

    /* Arm the timeout callout before dropping the mutex so expiry and
     * signal wakeups share one wait state.  The callback may fire before
     * the first yield on SMP, so the wait path must re-check the reason in
     * a loop rather than assuming one yield is sufficient.
     */
    u64 ticks = time_ms_to_ticks(timeout.ms);
    callout_set_ticks(&tmo, ticks, condvar_timeout_fn, &wqe);

    pi_mutex_unlock(mtx);

    for (;;) {
        sched_yield_trap();
        if (realtime_clock_wait_should_restart(wqe.task))
            break;
        if (wait_should_exit(wqe.reason))
            break;
        prepare_to_wait(&cv->wq, &wqe);
    }

    /* Ensure the timeout callback has completed before destroying wqe. */
    callout_cancel_sync(&tmo);
    finish_wait(&cv->wq, &wqe);

    bool timed_out = (wqe.reason == WAIT_UNBLOCK_TIMEOUT);
    i32 abort = 0;
    if (wqe.reason == WAIT_UNBLOCK_DESTROY)
        abort = wait_abort_error_current();

    pi_mutex_lock(mtx);
    /* Only honor a clock-settime restart when the wakeup was NOT a real
     * cv_{signal,broadcast} (WAIT_UNBLOCK_WAKEUP). If we restarted on a genuine
     * wakeup that raced with SYS_CLOCK_SETTIME the caller would re-enter the
     * wait and drop the signal on the floor. Timeout and destroy already steer
     * to other branches above.
     */
    if (abort == 0 && wqe.reason != WAIT_UNBLOCK_WAKEUP && !timed_out &&
        realtime_clock_wait_should_restart(wqe.task))
        return MAZU_WAIT_ABORT_CLOCK_SETTIME;
    if (abort < 0)
        return abort;
    return timed_out ? -(i32) ETIMEDOUT : 0;
}

void condvar_signal(struct condvar *cv)
{
    wake_up(&cv->wq, 1);
}

void condvar_broadcast(struct condvar *cv)
{
    wake_up(&cv->wq, 0);
}

#include __INC_TEST(condvar)
