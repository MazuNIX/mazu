/* SPDX-License-Identifier: MIT */
/* POSIX interval timer implementation.
 *
 * Pool-allocated timers backed by callout engine. On expiry, delivers
 * SIGALRM to the owning process. Tracks overrun count for missed expirations.
 */

#include "posix_timer.h"
#include <mazu/init.h>
#include <mazu/proc.h>
#include <mazu/spinlock.h>
#include <mazu/time.h>
#include "../proc/signal.h"

static struct posix_timer timer_pool[POSIX_TIMER_MAX];
static spinlock_t timer_lock = SPINLOCK_INITIALIZER;

static inline bool posix_timer_owner_alive(const struct posix_timer *t)
{
    struct proc *owner = t->owner;

    return owner && owner->magic == PROC_MAGIC &&
           t->owner_generation == owner->generation &&
           owner->state != PROC_STATE_ZOMBIE && owner->state != PROC_STATE_FREE;
}

static bool posix_timer_signal_pending_locked(struct proc *owner, i32 signo)
{
    u32 mask = sig_bit(signo);
    u64 sflags = proc_sig_lock_irqsave(owner);
    if ((owner->sig_state.proc_pending & mask) != 0) {
        proc_sig_unlock_irqrestore(owner, sflags);
        return true;
    }
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        struct sched_task *td = owner->tasks[i];
        if (td && (td->td_sig.pending & mask)) {
            proc_sig_unlock_irqrestore(owner, sflags);
            return true;
        }
    }
    proc_sig_unlock_irqrestore(owner, sflags);
    return false;
}

static bool posix_timer_target_is_live(const struct sched_task *td)
{
    return td && td->td_join_state != TD_JOIN_EXITED &&
           td->td_join_state != TD_JOIN_REAPED &&
           td->state != TD_STATE_TERMINATING;
}

i32 posix_timer_alloc(struct proc *p)
{
    if (!p)
        return -(i32) EINVAL;

    u64 flags = spin_lock_irqsave(&timer_lock);
    for (i32 i = 0; i < POSIX_TIMER_MAX; i++) {
        if (!timer_pool[i].in_use) {
            timer_pool[i].in_use = true;
            timer_pool[i].owner = p;
            timer_pool[i].owner_generation = p->generation;
            timer_pool[i].armed = false;
            timer_pool[i].overrun = 0;
            timer_pool[i].interval_ticks = 0;
            timer_pool[i].target_tid = 0;
            timer_pool[i].refcount = 1;
            callout_init(&timer_pool[i].co);
            spin_unlock_irqrestore(&timer_lock, flags);
            return i;
        }
    }
    spin_unlock_irqrestore(&timer_lock, flags);
    return -(i32) EAGAIN;
}

struct posix_timer *posix_timer_ptr(u16 object_index)
{
    if (object_index >= POSIX_TIMER_MAX)
        return NULL;
    return &timer_pool[object_index];
}

static void posix_timer_free(struct posix_timer *t)
{
    t->armed = false;
    callout_cancel_sync(&t->co);

    u64 flags = spin_lock_irqsave(&timer_lock);
    t->in_use = false;
    t->owner = NULL;
    t->owner_generation = 0;
    t->interval_ticks = 0;
    t->overrun = 0;
    t->target_tid = 0;
    t->refcount = 0;
    spin_unlock_irqrestore(&timer_lock, flags);
}

void posix_timer_put_idx(u16 object_index)
{
    struct posix_timer *t = posix_timer_ptr(object_index);
    if (!t || !t->in_use)
        return;
    u32 rc = __atomic_sub_fetch(&t->refcount, 1, __ATOMIC_ACQ_REL);
    if (rc == 0)
        posix_timer_free(t);
}

static void timer_expiry_fn(void *arg)
{
    struct posix_timer *t = arg;
    if (!t->armed || !t->in_use || !t->owner)
        return;

    /* Deliver SIGALRM.  Validate the owner is still a live process
     * (proc_exit sets state to ZOMBIE before detaching its tasks).
     */
    struct proc *owner = t->owner;
    if (!posix_timer_owner_alive(t)) {
        t->armed = false;
        return;
    }
    if (t->target_tid != 0) {
        u64 tflags = proc_table_lock_irqsave();
        struct sched_task *target = NULL;
        for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
            struct sched_task *td = owner->tasks[i];
            if (td && td->id == t->target_tid &&
                posix_timer_target_is_live(td)) {
                target = td;
                break;
            }
        }
        if (target) {
            u64 sflags = proc_sig_lock_irqsave(owner);
            __atomic_or_fetch(&target->td_sig.pending, sig_bit(SIGALRM),
                              __ATOMIC_RELAXED);
            proc_sig_unlock_irqrestore(owner, sflags);
            if (target->state == TD_STATE_SLEEPING)
                sched_wake_sleeping(target);
        }
        proc_table_unlock_irqrestore(tflags);
    } else {
        signal_send(owner, SIGALRM);
    }

    if (t->interval_ticks > 0) {
        if (!t->armed)
            return;
        u64 tflags = proc_table_lock_irqsave();
        bool alrm_pending = posix_timer_signal_pending_locked(owner, SIGALRM);
        proc_table_unlock_irqrestore(tflags);
        if (alrm_pending)
            t->overrun++;
        callout_set_ticks(&t->co, t->interval_ticks, timer_expiry_fn, t);
    } else {
        t->armed = false;
    }
}

i32 posix_timer_settime_idx(u16 object_index,
                            u64 value_ms,
                            u64 interval_ms,
                            u16 target_tid)
{
    if (object_index >= POSIX_TIMER_MAX)
        return -(i32) EINVAL;

    struct posix_timer *t = &timer_pool[object_index];
    if (!t->in_use)
        return -(i32) EINVAL;
    struct proc *caller = t->owner;
    if (!caller || t->owner_generation != caller->generation)
        return -(i32) EINVAL;

    if (target_tid != 0) {
        u64 tflags = proc_table_lock_irqsave();
        bool found = false;
        for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
            struct sched_task *td = caller->tasks[i];
            if (td && td->id == target_tid && posix_timer_target_is_live(td)) {
                found = true;
                break;
            }
        }
        proc_table_unlock_irqrestore(tflags);
        if (!found)
            return -(i32) ESRCH;
    }

    callout_cancel_sync(&t->co);
    t->target_tid = target_tid;

    if (value_ms == 0) {
        t->armed = false;
        t->interval_ticks = 0;
        return 0;
    }

    t->interval_ticks = (interval_ms > 0) ? time_ms_to_ticks(interval_ms) : 0;
    if (interval_ms > 0 && t->interval_ticks == 0)
        t->interval_ticks = 1;
    t->overrun = 0;
    t->armed = true;

    u64 ticks = time_ms_to_ticks(value_ms);
    if (ticks == 0)
        ticks = 1;
    callout_set_ticks(&t->co, ticks, timer_expiry_fn, t);

    return 0;
}

i64 posix_timer_gettime_idx(u16 object_index)
{
    if (object_index >= POSIX_TIMER_MAX)
        return -(i64) EINVAL;
    struct posix_timer *t = &timer_pool[object_index];
    if (!t->in_use)
        return -(i64) EINVAL;
    if (!t->armed)
        return 0;
    u64 now = time_rdtime();
    u64 deadline = t->co.deadline;
    if (deadline <= now)
        return 0;
    return (i64) time_ticks_to_ms(deadline - now);
}

i64 posix_timer_getoverrun_idx(u16 object_index)
{
    if (object_index >= POSIX_TIMER_MAX)
        return -(i64) EINVAL;
    struct posix_timer *t = &timer_pool[object_index];
    if (!t->in_use)
        return -(i64) EINVAL;
    return (i64) t->overrun;
}

void posix_timer_teardown_proc(struct proc *p)
{
    for (i32 i = 0; i < POSIX_TIMER_MAX; i++) {
        struct posix_timer *t = &timer_pool[i];
        if (t->in_use && t->owner == p && t->owner_generation == p->generation)
            posix_timer_free(t);
    }
}

static void posix_timer_boot_init(u32 flag __unused)
{
    for (i32 i = 0; i < POSIX_TIMER_MAX; i++) {
        timer_pool[i].in_use = false;
        timer_pool[i].refcount = 0;
        callout_init(&timer_pool[i].co);
    }
}
DEFINE_INIT_HOOK(posix_timer_boot_init, INIT_LEVEL_SUBSYS, INIT_FLAG_PRIMARY);

#include __INC_TEST(posix_timer)
