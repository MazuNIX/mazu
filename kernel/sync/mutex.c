/* SPDX-License-Identifier: MIT */
/* Priority-inheriting mutex.
 *
 * Waiters are kept in descending priority order.  When a task blocks, its
 * priority is compared with the owner's; if higher, the owner is boosted. On
 * unlock, the highest-priority waiter (head of the list) receives direct
 * ownership handover (no barging window), and the old owner's priority is
 * recomputed from any remaining held PI mutexes.
 *
 * PI propagation follows a bounded wait chain: if A holds M1, B holds M2 and
 * waits on M1, and C waits on M2, C's effective priority can flow through B to
 * A. When waiters time out or go away, the same chain refresh path deboosts
 * upstream owners back toward their exact effective priority.
 */

#include "mutex.h"
#include <mazu/assert.h>
#include <mazu/callout.h>
#include <mazu/eventlog.h>
#include <mazu/ipi.h>
#include <mazu/sched.h>
#include <mazu/spinlock.h>
#include "../lockdep.h"
#include "../proc/signal.h"
#include "futex.h"

struct pi_mutex_waiter {
    struct sched_task *task;
    struct list_head node;
    bool granted; /* set by unlock to signal direct ownership handover */
};

struct pi_mutex_cleanup_ctx {
    struct pi_mutex *mtx;
    struct pi_mutex_waiter *waiter;
    struct callout *timeout_callout;
};

#define PI_CHAIN_MAX 32

static inline void pi_refresh_owner_chain(struct sched_task *owner)
{
    if (owner && owner->td_waiting_on_task)
        pi_mutex_refresh_prio(owner);
}

static u8 pi_mutex_refresh_waiters_locked(struct pi_mutex *mtx,
                                          struct pi_mutex_waiter **best_out)
{
    u8 top_prio = 0;
    struct pi_mutex_waiter *best = NULL;
    struct pi_mutex_waiter *it;

    list_for_each_entry_safe (&mtx->waiters, it, struct pi_mutex_waiter, node) {
        if (it->task->state == TD_STATE_TERMINATING)
            continue;
        if (!best || it->task->td_prio > best->task->td_prio) {
            best = it;
            top_prio = it->task->td_prio;
        }
    }

    mtx->top_waiter_prio = top_prio;
    if (best_out)
        *best_out = best;
    return top_prio;
}

/* Compute the effective priority for task without touching its td_pi_lock.
 * Caller must hold task->td_pi_lock so the pi_held_mutexes walk does not
 * race with concurrent list mutations from cross-hart lock/unlock paths.
 * The per-mutex top_waiter_prio is loaded relaxed: foreign mutexes update
 * it under their own mtx->lock, and a stale read is transient because the
 * next priority refresh on that mutex will converge.
 */
static u8 pi_compute_prio_locked(struct sched_task *task)
{
    u8 max_prio = task->td_base_prio;
    if (task->td_futex_pi_prio > max_prio)
        max_prio = task->td_futex_pi_prio;
    struct pi_mutex *m;

    list_for_each_entry_safe (&task->pi_held_mutexes, m, struct pi_mutex,
                              pi_held) {
        u8 wp = __atomic_load_n(&m->top_waiter_prio, __ATOMIC_RELAXED);
        if (wp > max_prio)
            max_prio = wp;
    }
    return max_prio;
}

static void pi_set_wait_dependency(struct sched_task *waiter,
                                   struct pi_mutex *mtx,
                                   struct sched_task *owner)
{
    waiter->td_waiting_on_mutex = mtx;
    waiter->td_waiting_on_futex = NULL;
    waiter->td_waiting_on_task = owner;
}

static void pi_clear_wait_dependency(struct sched_task *waiter)
{
    waiter->td_waiting_on_mutex = NULL;
    waiter->td_waiting_on_futex = NULL;
    waiter->td_waiting_on_task = NULL;
}

static void pi_recompute_prio_locked(struct sched_task *task)
{
    task->td_prio = pi_compute_prio_locked(task);
}

static void pi_recompute_prio(struct sched_task *task)
{
    u64 flags = spin_lock_irqsave(&task->td_pi_lock);
    pi_recompute_prio_locked(task);
    spin_unlock_irqrestore(&task->td_pi_lock, flags);
}

void pi_mutex_refresh_prio(struct sched_task *task)
{
    struct sched_task *cur = task;

    for (u32 depth = 0; cur && depth < PI_CHAIN_MAX; depth++) {
        pi_recompute_prio(cur);

        if (cur->td_waiting_on_mutex) {
            cur = pi_mutex_refresh_wait_chain(cur->td_waiting_on_mutex);
            continue;
        }
        if (cur->td_waiting_on_futex) {
            cur = futex_pi_refresh_wait_chain(cur->td_waiting_on_futex);
            continue;
        }
        break;
    }
}

/* Variant called from contexts that already hold the target task's
 * td_pi_lock (currently the futex side after it has finished mutating
 * pi_held_futexes / td_futex_pi_prio under that same lock).
 */
void pi_mutex_refresh_prio_local(struct sched_task *task)
{
    if (task)
        pi_recompute_prio_locked(task);
}

struct sched_task *pi_mutex_refresh_wait_chain(struct pi_mutex *mtx)
{
    if (!mtx)
        return NULL;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mtx->lock);
    pi_mutex_refresh_waiters_locked(mtx, NULL);
    struct sched_task *owner = mtx->owner;
    spin_unlock_irqrestore(&mtx->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return owner;
}

static void pi_mutex_wait_cleanup(struct sched_task *task, void *ctx_ptr)
{
    struct pi_mutex_cleanup_ctx *ctx = ctx_ptr;
    assert(task);
    assert(ctx);

    if (ctx->timeout_callout)
        callout_cancel_sync(ctx->timeout_callout);

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&ctx->mtx->lock);
    if (ctx->waiter->node.next != &ctx->waiter->node)
        list_del_init(&ctx->waiter->node);
    pi_mutex_refresh_waiters_locked(ctx->mtx, NULL);
    struct sched_task *owner = ctx->mtx->owner;
    if (owner)
        pi_recompute_prio(owner);

    spin_unlock_irqrestore(&ctx->mtx->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    pi_refresh_owner_chain(owner);
}

void pi_mutex_init(struct pi_mutex *mtx)
{
    mtx->lock = (spinlock_t) SPINLOCK_INITIALIZER;
    mtx->owner = NULL;
    list_init(&mtx->waiters);
    list_init(&mtx->pi_held);
    mtx->top_waiter_prio = 0;
}

i32 pi_mutex_lock_interruptible(struct pi_mutex *mtx)
{
    struct sched_task *self = sched_current_task();
    struct pi_mutex_waiter w = {.task = self, .granted = false};
    struct pi_mutex_cleanup_ctx cleanup = {
        .mtx = mtx,
        .waiter = &w,
        .timeout_callout = NULL,
    };
    list_init(&w.node);
    DEBUG_ASSERT(!in_interrupt_context());

    for (;;) {
        lockdep_acquire(LOCK_LEVEL_WAITQ);
        u64 flags = spin_lock_irqsave(&mtx->lock);

        i32 abort = wait_abort_error_current();
        if (abort < 0 && w.node.next != &w.node && !w.granted) {
            list_del_init(&w.node);
            pi_mutex_refresh_waiters_locked(mtx, NULL);
            struct sched_task *owner = mtx->owner;
            if (owner)
                pi_recompute_prio(owner);
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            if (self->state == TD_STATE_BLOCKED)
                sched_set_task_state(self, TD_STATE_RUNNING);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            pi_refresh_owner_chain(owner);
            return abort;
        }

        /* Direct handover: unlock or release_all has already transferred
         * ownership and linked mtx->pi_held into self->pi_held_mutexes
         * under self's td_pi_lock.  Re-linking is a defensive no-op for
         * the rare case where a future donor variant skips the link;
         * take td_pi_lock(self) so the check-and-add is atomic.
         */
        if (w.granted) {
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            u64 pf = task_pi_lock(self);
            if (mtx->pi_held.next == &mtx->pi_held)
                list_add(&self->pi_held_mutexes, &mtx->pi_held);
            task_pi_unlock(self, pf);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return 0;
        }

        /* Non-recursive mutex: locking while already held by self is a bug
         * because the subsequent unlock would release prematurely.
         */
        ALWAYS_ASSERT(mtx->owner != self);

        if (!mtx->owner) {
            if (w.node.next != &w.node) {
                list_del_init(&w.node);
                pi_mutex_refresh_waiters_locked(mtx, NULL);
            }
            mtx->owner = self;
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            u64 pf = task_pi_lock(self);
            list_add(&self->pi_held_mutexes, &mtx->pi_held);
            task_pi_unlock(self, pf);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return 0;
        }

        pi_set_wait_dependency(self, mtx, mtx->owner);

        /* Insert into waiter list in descending priority order once. */
        if (w.node.next == &w.node) {
            struct list_head *pos = &mtx->waiters;
            struct pi_mutex_waiter *it;
            list_for_each_entry_safe (&mtx->waiters, it, struct pi_mutex_waiter,
                                      node) {
                if (it->task->td_prio < self->td_prio) {
                    pos = &it->node;
                    break;
                }
            }
            list_add_tail(pos, &w.node);
        }
        pi_mutex_refresh_waiters_locked(mtx, NULL);
        struct sched_task *owner = mtx->owner;
        if (owner)
            pi_recompute_prio(owner);
        sched_set_task_state(self, TD_STATE_BLOCKED);
        sched_set_block_cleanup(self, pi_mutex_wait_cleanup, &cleanup);

        spin_unlock_irqrestore(&mtx->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        pi_refresh_owner_chain(owner);

        sched_yield_trap();
    }
}

void pi_mutex_lock(struct pi_mutex *mtx)
{
    i32 rc = pi_mutex_lock_interruptible(mtx);
    ALWAYS_ASSERT(rc == 0);
}

struct pi_mutex_timeout_ctx {
    struct pi_mutex *mtx;
    struct pi_mutex_waiter *waiter;
    volatile bool timed_out;
};

static void pi_mutex_timeout_fn(void *arg)
{
    struct pi_mutex_timeout_ctx *ctx = arg;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&ctx->mtx->lock);

    if (ctx->waiter->node.next != &ctx->waiter->node && !ctx->waiter->granted &&
        ctx->waiter->task->state != TD_STATE_TERMINATING) {
        list_del_init(&ctx->waiter->node);
        pi_mutex_refresh_waiters_locked(ctx->mtx, NULL);
        struct sched_task *owner = ctx->mtx->owner;
        if (owner)
            pi_recompute_prio(owner);
        ctx->timed_out = true;
        sched_wake_ready(ctx->waiter->task);
        spin_unlock_irqrestore(&ctx->mtx->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        pi_refresh_owner_chain(owner);
        return;
    }

    spin_unlock_irqrestore(&ctx->mtx->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
}

i32 pi_mutex_lock_timed(struct pi_mutex *mtx, struct time_ms timeout)
{
    struct sched_task *self = sched_current_task();
    struct pi_mutex_waiter w = {.task = self, .granted = false};
    struct pi_mutex_timeout_ctx tctx = {
        .mtx = mtx,
        .waiter = &w,
        .timed_out = false,
    };
    struct callout tmo;
    struct pi_mutex_cleanup_ctx cleanup = {
        .mtx = mtx,
        .waiter = &w,
        .timeout_callout = &tmo,
    };
    list_init(&w.node);
    callout_init(&tmo);
    DEBUG_ASSERT(!in_interrupt_context());

    for (;;) {
        lockdep_acquire(LOCK_LEVEL_WAITQ);
        u64 flags = spin_lock_irqsave(&mtx->lock);

        i32 abort = wait_abort_error_current();
        if (w.granted) {
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            if (self->state == TD_STATE_BLOCKED)
                sched_set_task_state(self, TD_STATE_RUNNING);
            u64 pf = task_pi_lock(self);
            if (mtx->pi_held.next == &mtx->pi_held)
                list_add(&self->pi_held_mutexes, &mtx->pi_held);
            task_pi_unlock(self, pf);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            callout_cancel_sync(&tmo);
            return 0;
        }
        if (abort < 0 && w.node.next != &w.node) {
            list_del_init(&w.node);
            pi_mutex_refresh_waiters_locked(mtx, NULL);
            struct sched_task *owner = mtx->owner;
            if (owner)
                pi_recompute_prio(owner);
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            if (self->state == TD_STATE_BLOCKED)
                sched_set_task_state(self, TD_STATE_RUNNING);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            callout_cancel_sync(&tmo);
            pi_refresh_owner_chain(owner);
            return abort;
        }
        if (tctx.timed_out) {
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            if (self->state == TD_STATE_BLOCKED)
                sched_set_task_state(self, TD_STATE_RUNNING);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            callout_cancel_sync(&tmo);
            return -(i32) ETIMEDOUT;
        }

        ALWAYS_ASSERT(mtx->owner != self);

        if (!mtx->owner) {
            if (w.node.next != &w.node) {
                list_del_init(&w.node);
                pi_mutex_refresh_waiters_locked(mtx, NULL);
            }
            mtx->owner = self;
            pi_clear_wait_dependency(self);
            sched_clear_block_cleanup(self);
            if (self->state == TD_STATE_BLOCKED)
                sched_set_task_state(self, TD_STATE_RUNNING);
            u64 pf = task_pi_lock(self);
            list_add(&self->pi_held_mutexes, &mtx->pi_held);
            task_pi_unlock(self, pf);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            callout_cancel_sync(&tmo);
            return 0;
        }

        pi_set_wait_dependency(self, mtx, mtx->owner);

        if (w.node.next == &w.node) {
            struct list_head *pos = &mtx->waiters;
            struct pi_mutex_waiter *it;
            list_for_each_entry_safe (&mtx->waiters, it, struct pi_mutex_waiter,
                                      node) {
                if (it->task->td_prio < self->td_prio) {
                    pos = &it->node;
                    break;
                }
            }
            list_add_tail(pos, &w.node);
            callout_set_ticks(&tmo, time_ms_to_ticks(timeout.ms),
                              pi_mutex_timeout_fn, &tctx);
        }
        pi_mutex_refresh_waiters_locked(mtx, NULL);
        struct sched_task *owner = mtx->owner;
        if (owner)
            pi_recompute_prio(owner);
        sched_set_task_state(self, TD_STATE_BLOCKED);
        sched_set_block_cleanup(self, pi_mutex_wait_cleanup, &cleanup);

        spin_unlock_irqrestore(&mtx->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        pi_refresh_owner_chain(owner);

        sched_yield_trap();
    }
}

i32 pi_mutex_trylock(struct pi_mutex *mtx)
{
    struct sched_task *self = sched_current_task();

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mtx->lock);

    if (mtx->owner) {
        spin_unlock_irqrestore(&mtx->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i32) EBUSY;
    }

    mtx->owner = self;
    u64 pf = task_pi_lock(self);
    list_add(&self->pi_held_mutexes, &mtx->pi_held);
    task_pi_unlock(self, pf);
    spin_unlock_irqrestore(&mtx->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return 0;
}

void pi_mutex_unlock(struct pi_mutex *mtx)
{
    struct sched_task *self = sched_current_task();

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mtx->lock);

    /* Check ownership under the lock so unlock stays serialized with
     * concurrent lockers and wakeups on other harts.
     */
    ALWAYS_ASSERT(mtx->owner == self);

    /* Remove this mutex from the owner's held chain before recomputing
     * priority.  This mutex's waiters should no longer influence old owner's
     * boost level.  td_pi_lock(self) covers the list mutation and the
     * subsequent recompute as a single atomic step.
     */
    u64 spf = task_pi_lock(self);
    list_del_init(&mtx->pi_held);
    pi_recompute_prio_locked(self);
    task_pi_unlock(self, spf);
    struct sched_task *old_owner = self;

    if (list_empty(&mtx->waiters)) {
        mtx->owner = NULL;
        spin_unlock_irqrestore(&mtx->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        pi_refresh_owner_chain(old_owner);
        return;
    }

    /* Direct handover: transfer ownership to the highest-priority waiter under
     * the lock, preventing third-party barging.
     */
    struct pi_mutex_waiter *w = NULL;
    pi_mutex_refresh_waiters_locked(mtx, &w);
    ALWAYS_ASSERT(w != NULL);
    list_del_init(&w->node);

    pi_mutex_refresh_waiters_locked(mtx, NULL);

    mtx->owner = w->task;
    w->granted = true;
    /* Link the mutex into the new owner's pi_held_mutexes under mtx->lock
     * so pi_recompute_prio on the new owner sees remaining waiters
     * immediately, with no window between wake and the lock path resuming.
     * Hold td_pi_lock(w->task) across both operations.
     */
    u64 wpf = task_pi_lock(w->task);
    list_add(&w->task->pi_held_mutexes, &mtx->pi_held);
    pi_recompute_prio_locked(w->task);
    task_pi_unlock(w->task, wpf);
    sched_wake_ready(w->task);

    spin_unlock_irqrestore(&mtx->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    pi_refresh_owner_chain(old_owner);
}

void pi_mutex_release_all(struct sched_task *task)
{
    assert(task);

    for (;;) {
        /* Peek the next held mutex under td_pi_lock(task) so the head read
         * does not race with concurrent walks (e.g. cross-hart priority
         * recompute) that traverse the same list.  The peek must be
         * dropped before taking mtx->lock to preserve the documented
         * lock order (mtx->lock at WAITQ; td_pi_lock is innermost).
         */
        u64 pf = task_pi_lock(task);
        if (list_empty(&task->pi_held_mutexes)) {
            task_pi_unlock(task, pf);
            return;
        }
        struct pi_mutex *mtx =
            list_entry(task->pi_held_mutexes.next, struct pi_mutex, pi_held);
        task_pi_unlock(task, pf);

        lockdep_acquire(LOCK_LEVEL_WAITQ);
        u64 flags = spin_lock_irqsave(&mtx->lock);

        if (mtx->owner != task) {
            u64 pf2 = task_pi_lock(task);
            list_del_init(&mtx->pi_held);
            task_pi_unlock(task, pf2);
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            continue;
        }

        u64 pf2 = task_pi_lock(task);
        list_del_init(&mtx->pi_held);
        task_pi_unlock(task, pf2);

        if (list_empty(&mtx->waiters)) {
            mtx->owner = NULL;
            mtx->top_waiter_prio = 0;
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            continue;
        }

        /* Skip waiters that are already terminating — waking them would
         * revive a task that should stay dead.
         */
        struct pi_mutex_waiter *w = NULL;
        pi_mutex_refresh_waiters_locked(mtx, &w);
        if (w)
            list_del_init(&w->node);

        if (!w) {
            mtx->owner = NULL;
            mtx->top_waiter_prio = 0;
            spin_unlock_irqrestore(&mtx->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            continue;
        }

        pi_mutex_refresh_waiters_locked(mtx, NULL);

        mtx->owner = w->task;
        w->granted = true;
        u64 wpf = task_pi_lock(w->task);
        list_add(&w->task->pi_held_mutexes, &mtx->pi_held);
        pi_recompute_prio_locked(w->task);
        task_pi_unlock(w->task, wpf);
        sched_wake_ready(w->task);

        spin_unlock_irqrestore(&mtx->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
    }
}

#include __INC_TEST(mutex)
