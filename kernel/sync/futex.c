/* SPDX-License-Identifier: MIT */
/* Futex implementation: hash table of per-bucket wait lists.
 *
 * Each hash bucket holds a list of waiters keyed by user virtual address.
 * FUTEX_WAIT reads the user word under the bucket lock to prevent lost
 * wakeups (the lock serializes the read-check-sleep sequence with FUTEX_WAKE).
 *
 * 64 buckets with a multiplicative hash; sufficient for an embedded kernel
 * where the total number of concurrent futex addresses is small.
 */

#include "futex.h"
#include <mazu/eventlog.h>
#include <mazu/init.h>
#include <mazu/initgraph.h>
#include <mazu/list.h>
#include <mazu/print.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/spinlock.h>
#include <mazu/uaccess.h>
#include "../lockdep.h"
#include "../proc/signal.h"
#include "../sync/mutex.h"

#define FUTEX_HASH_BITS 6
#define FUTEX_HASH_SIZE (1U << FUTEX_HASH_BITS)
/* PI states are statically allocated from this pool.  Sized for the
 * worst-case fan-out of pthread PI mutexes across all processes/threads
 * the RTOS expects to host; raising it costs ~64 bytes per slot.
 */
#define FUTEX_PI_STATE_MAX 256
#define FUTEX_OWNER_DIED 0x40000000U
#define FUTEX_TID_MASK (~FUTEX_OWNER_DIED)

struct futex_bucket;
struct futex_pi_state;

struct futex_waiter {
    ptr key; /* user virtual address */
    struct sched_task *task;
    struct futex_bucket *bucket; /* current wait bucket; updated on requeue */
    struct futex_pi_state *pi_state;
    bool pi_wait;
    struct list_head node;
};

struct futex_pi_state {
    bool in_use;
    ptr key;
    struct sched_task *owner;
    u8 top_waiter_prio;
    bool owner_died;
    struct list_head node;
    struct list_head owner_link;
};

struct futex_bucket {
    spinlock_t lock;
    struct list_head waiters;
    struct list_head pi_states;
};

struct futex_cleanup_ctx {
    struct futex_waiter *waiter;
};

static struct futex_bucket futex_table[FUTEX_HASH_SIZE];
static spinlock_t futex_pi_state_lock = SPINLOCK_INITIALIZER;
static struct futex_pi_state futex_pi_states[FUTEX_PI_STATE_MAX];

static u32 futex_hash(ptr addr);
static struct futex_pi_state *futex_pi_state_lookup_locked(
    struct futex_bucket *b,
    ptr key);
static u8 futex_pi_refresh_waiters_locked(struct futex_bucket *b,
                                          ptr key,
                                          struct futex_waiter **best_out);

static inline void futex_pi_refresh_owner_chain(struct sched_task *owner)
{
    if (owner && owner->td_waiting_on_task)
        pi_mutex_refresh_prio(owner);
}

static void futex_pi_set_wait_dependency(struct sched_task *waiter,
                                         struct futex_pi_state *st)
{
    waiter->td_waiting_on_mutex = NULL;
    waiter->td_waiting_on_futex = st;
    waiter->td_waiting_on_task = st ? st->owner : NULL;
}

static void futex_pi_clear_wait_dependency(struct sched_task *waiter)
{
    waiter->td_waiting_on_mutex = NULL;
    waiter->td_waiting_on_futex = NULL;
    waiter->td_waiting_on_task = NULL;
}

struct futex_find_task_ctx {
    u32 tid;
    struct sched_task *found;
};

static void futex_find_task_cb(struct proc *p, void *ctx_ptr)
{
    struct futex_find_task_ctx *ctx = ctx_ptr;

    for (u8 i = 0; i < PROC_THREAD_MAX && !ctx->found; i++) {
        struct sched_task *td = p->tasks[i];
        if (td && td->id == ctx->tid && td->state != TD_STATE_TERMINATING) {
            ctx->found = td;
            break;
        }
    }
}

static void futex_pi_refresh_task_locked(struct sched_task *task)
{
    if (!task)
        return;

    /* Serialize the pi_held_futexes walk and the td_futex_pi_prio /
     * td_prio writes through the per-task PI lock so cross-hart updates
     * to different PI futexes owned by the same task cannot race against
     * each other.  pi_mutex_refresh_prio_local expects the lock held.
     */
    u64 pf = task_pi_lock(task);
    task->td_futex_pi_prio = 0;
    struct futex_pi_state *it;
    list_for_each_entry_safe (&task->pi_held_futexes, it, struct futex_pi_state,
                              owner_link) {
        if (it->top_waiter_prio > task->td_futex_pi_prio)
            task->td_futex_pi_prio = it->top_waiter_prio;
    }
    pi_mutex_refresh_prio_local(task);
    task_pi_unlock(task, pf);
}

struct sched_task *futex_pi_refresh_wait_chain(struct futex_pi_state *st)
{
    if (!st)
        return NULL;

    u32 idx = futex_hash(st->key);
    struct futex_bucket *b = &futex_table[idx];

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&b->lock);
    if (futex_pi_state_lookup_locked(b, st->key) != st) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return NULL;
    }
    st->top_waiter_prio = futex_pi_refresh_waiters_locked(b, st->key, NULL);
    struct sched_task *owner = st->owner;
    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return owner;
}

static struct sched_task *futex_find_task_by_tid(u32 tid)
{
    if (tid == 0)
        return NULL;

    struct futex_find_task_ctx ctx = {
        .tid = tid,
        .found = NULL,
    };
    proc_for_each(futex_find_task_cb, &ctx);
    return ctx.found;
}

static struct futex_pi_state *futex_pi_state_lookup_locked(
    struct futex_bucket *b,
    ptr key)
{
    struct futex_pi_state *st;
    list_for_each_entry_safe (&b->pi_states, st, struct futex_pi_state, node) {
        if (st->key == key)
            return st;
    }
    return NULL;
}

static struct futex_pi_state *futex_pi_state_get_locked(struct futex_bucket *b,
                                                        ptr key,
                                                        bool create)
{
    struct futex_pi_state *st = futex_pi_state_lookup_locked(b, key);
    if (st || !create)
        return st;

    u64 flags = spin_lock_irqsave(&futex_pi_state_lock);
    for (u32 i = 0; i < FUTEX_PI_STATE_MAX; i++) {
        if (!futex_pi_states[i].in_use) {
            st = &futex_pi_states[i];
            memset(st, 0, sizeof(*st));
            st->in_use = true;
            st->key = key;
            list_init(&st->node);
            list_init(&st->owner_link);
            list_add_tail(&b->pi_states, &st->node);
            break;
        }
    }
    spin_unlock_irqrestore(&futex_pi_state_lock, flags);
    return st;
}

static void futex_pi_state_maybe_free_locked(struct futex_bucket *b,
                                             struct futex_pi_state *st)
{
    if (!st || st->owner || st->top_waiter_prio != 0 || st->owner_died)
        return;
    if (st->owner_link.next != &st->owner_link)
        list_del_init(&st->owner_link);
    if (st->node.next != &st->node)
        list_del_init(&st->node);
    u64 flags = spin_lock_irqsave(&futex_pi_state_lock);
    memset(st, 0, sizeof(*st));
    spin_unlock_irqrestore(&futex_pi_state_lock, flags);
    (void) b;
}

static void futex_pi_link_owner_locked(struct futex_pi_state *st,
                                       struct sched_task *owner)
{
    /* Each owner_link mutation touches a task's pi_held_futexes list head,
     * so the unlink must hold the previous owner's td_pi_lock and the
     * relink must hold the new owner's lock.  Caller already serializes
     * st->owner reads/writes through the futex bucket lock, so prev is
     * stable across the unlink critical section.
     */
    struct sched_task *prev = st->owner;
    if (st->owner_link.next != &st->owner_link) {
        if (prev) {
            u64 pf = task_pi_lock(prev);
            list_del_init(&st->owner_link);
            task_pi_unlock(prev, pf);
        } else {
            list_del_init(&st->owner_link);
        }
    }
    st->owner = owner;
    if (owner) {
        u64 pf = task_pi_lock(owner);
        list_add(&owner->pi_held_futexes, &st->owner_link);
        task_pi_unlock(owner, pf);
    }
}

static u8 futex_pi_refresh_waiters_locked(struct futex_bucket *b,
                                          ptr key,
                                          struct futex_waiter **best_out)
{
    u8 top_prio = 0;
    struct futex_waiter *best = NULL;
    struct futex_waiter *w;

    list_for_each_entry_safe (&b->waiters, w, struct futex_waiter, node) {
        if (w->key != key || w->task->state != TD_STATE_BLOCKED)
            continue;
        if (!best || w->task->td_prio > best->task->td_prio) {
            best = w;
            top_prio = w->task->td_prio;
        }
    }

    if (best_out)
        *best_out = best;
    return top_prio;
}

static void futex_pi_recompute_owner_locked(struct futex_bucket *b,
                                            struct futex_pi_state *st)
{
    if (!st)
        return;
    st->top_waiter_prio = futex_pi_refresh_waiters_locked(b, st->key, NULL);
    futex_pi_refresh_task_locked(st->owner);
}

static void futex_wait_cleanup(struct sched_task *task, void *ctx_ptr)
{
    struct futex_cleanup_ctx *ctx = ctx_ptr;
    assert(task);
    assert(ctx);
    assert(ctx->waiter);
    assert(ctx->waiter->bucket);

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&ctx->waiter->bucket->lock);
    struct sched_task *owner = NULL;
    if (ctx->waiter->node.next != &ctx->waiter->node) {
        list_del_init(&ctx->waiter->node);
        if (ctx->waiter->pi_wait && ctx->waiter->pi_state) {
            futex_pi_recompute_owner_locked(ctx->waiter->bucket,
                                            ctx->waiter->pi_state);
            owner = ctx->waiter->pi_state->owner;
        }
    }
    if (ctx->waiter->pi_wait)
        futex_pi_clear_wait_dependency(task);
    spin_unlock_irqrestore(&ctx->waiter->bucket->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    futex_pi_refresh_owner_chain(owner);
}

static u32 futex_hash(ptr addr)
{
    /* Multiplicative hash: strip low 2 bits (u32 alignment), mix. */
    u64 h = (u64) addr >> 2;
    h *= 0x45d9f3bUL;
    h ^= h >> 16;
    return (u32) (h & (FUTEX_HASH_SIZE - 1));
}

void futex_init(void)
{
    for (u32 i = 0; i < FUTEX_HASH_SIZE; i++) {
        futex_table[i].lock = (spinlock_t) SPINLOCK_INITIALIZER;
        list_init(&futex_table[i].waiters);
        list_init(&futex_table[i].pi_states);
    }
}

i64 futex_wait(ptr uaddr, u32 expected)
{
    DEBUG_ASSERT(!in_interrupt_context());

    u32 idx = futex_hash(uaddr);
    struct futex_bucket *b = &futex_table[idx];

    struct futex_waiter w = {
        .key = uaddr,
        .task = sched_current_task(),
        .bucket = b,
        .pi_state = NULL,
        .pi_wait = false,
    };
    struct futex_cleanup_ctx cleanup = {
        .waiter = &w,
    };
    list_init(&w.node);

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&b->lock);

    /* Read the user futex word under the bucket lock.  The lock
     * serializes this read with futex_wake, preventing lost wakeups.
     */
    u32 val;
    i64 rc = copy_from_user(&val, uaddr, sizeof(val));
    if (rc < 0) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i64) EFAULT;
    }

    if (val != expected) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i64) EAGAIN;
    }

    /* Value matches: enqueue and block. */
    list_add_tail(&b->waiters, &w.node);
    sched_set_task_state(w.task, TD_STATE_BLOCKED);
    sched_set_block_cleanup(w.task, futex_wait_cleanup, &cleanup);

    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);

    sched_yield_trap();

    /* Clean up: remove from bucket if still linked (defensive). */
    lockdep_acquire(LOCK_LEVEL_WAITQ);
    flags = spin_lock_irqsave(&w.bucket->lock);
    list_del_init(&w.node);
    sched_clear_block_cleanup(w.task);
    if (w.task->state == TD_STATE_BLOCKED)
        sched_set_task_state(w.task, TD_STATE_RUNNING);
    spin_unlock_irqrestore(&w.bucket->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);

    i32 abort = wait_abort_error_current();
    if (abort < 0)
        return (i64) abort;
    return 0;
}

i64 futex_wake(ptr uaddr, u32 max_wake)
{
    u32 idx = futex_hash(uaddr);
    struct futex_bucket *b = &futex_table[idx];
    u32 woken = 0;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&b->lock);
    struct futex_waiter *w;
    struct sched_task *owner = NULL;

    list_for_each_entry_safe (&b->waiters, w, struct futex_waiter, node) {
        if (woken >= max_wake)
            break;
        if (w->key != uaddr)
            continue;
        if (w->task->state != TD_STATE_BLOCKED)
            continue;

        list_del_init(&w->node);
        if (w->pi_wait && w->pi_state) {
            futex_pi_clear_wait_dependency(w->task);
            futex_pi_recompute_owner_locked(b, w->pi_state);
            owner = w->pi_state->owner;
        }
        sched_wake_ready(w->task);
        woken++;
    }

    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    futex_pi_refresh_owner_chain(owner);

    return (i64) woken;
}

i64 futex_cmp_requeue(ptr uaddr1,
                      u32 expected,
                      ptr uaddr2,
                      u32 nr_wake,
                      u32 nr_requeue)
{
    u32 idx1 = futex_hash(uaddr1);
    u32 idx2 = futex_hash(uaddr2);
    struct futex_bucket *b1 = &futex_table[idx1];
    struct futex_bucket *b2 = &futex_table[idx2];

    /* Lock both buckets in address order to avoid ABBA deadlock. */
    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags;
    struct sched_task *owner = NULL;
    if (idx1 <= idx2) {
        flags = spin_lock_irqsave(&b1->lock);
        if (idx1 != idx2)
            spin_lock(&b2->lock);
    } else {
        flags = spin_lock_irqsave(&b2->lock);
        spin_lock(&b1->lock);
    }

    /* Check user word atomically with the bucket lock held. */
    u32 val;
    i64 rc = copy_from_user(&val, uaddr1, sizeof(val));
    if (rc < 0) {
        rc = -(i64) EFAULT;
        goto unlock;
    }
    if (val != expected) {
        rc = -(i64) EAGAIN;
        goto unlock;
    }

    u32 woken = 0;
    u32 requeued = 0;
    struct futex_waiter *w;

    list_for_each_entry_safe (&b1->waiters, w, struct futex_waiter, node) {
        if (w->key != uaddr1)
            continue;
        if (w->task->state != TD_STATE_BLOCKED)
            continue;

        if (woken < nr_wake) {
            list_del_init(&w->node);
            if (w->pi_wait && w->pi_state) {
                futex_pi_clear_wait_dependency(w->task);
                futex_pi_recompute_owner_locked(b1, w->pi_state);
                owner = w->pi_state->owner;
                w->pi_wait = false;
                w->pi_state = NULL;
            }
            sched_wake_ready(w->task);
            woken++;
        } else if (requeued < nr_requeue) {
            /* Move waiter from bucket 1 to bucket 2.
             * Keep cleanup active and retarget it to the new bucket so the
             * blocked task removes itself from the correct wait list on wake.
             */
            list_del_init(&w->node);
            if (w->pi_wait && w->pi_state) {
                futex_pi_clear_wait_dependency(w->task);
                futex_pi_recompute_owner_locked(b1, w->pi_state);
                owner = w->pi_state->owner;
                w->pi_wait = false;
                w->pi_state = NULL;
            }
            w->key = uaddr2;
            w->bucket = b2;
            list_add_tail(&b2->waiters, &w->node);
            requeued++;
        } else {
            break;
        }
    }

    rc = (i64) woken + (i64) requeued;

unlock:
    if (idx1 <= idx2) {
        if (idx1 != idx2)
            spin_unlock(&b2->lock);
        spin_unlock_irqrestore(&b1->lock, flags);
    } else {
        spin_unlock(&b1->lock);
        spin_unlock_irqrestore(&b2->lock, flags);
    }
    lockdep_release(LOCK_LEVEL_WAITQ);
    futex_pi_refresh_owner_chain(owner);
    return rc;
}

i64 futex_cmp_requeue_pi(ptr uaddr1,
                         u32 expected,
                         ptr uaddr2,
                         u32 nr_wake,
                         u32 nr_requeue)
{
    /* Requeue-to-self is a logic error: the source and destination
     * waitqueue are the same, so no waiter can transition between them
     * meaningfully.  Match Linux behavior and reject early.
     */
    if (uaddr1 == uaddr2)
        return -(i64) EINVAL;

    u32 idx1 = futex_hash(uaddr1);
    u32 idx2 = futex_hash(uaddr2);
    struct futex_bucket *b1 = &futex_table[idx1];
    struct futex_bucket *b2 = &futex_table[idx2];

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags;
    struct sched_task *src_owner = NULL;
    struct sched_task *dst_owner = NULL;
    if (idx1 <= idx2) {
        flags = spin_lock_irqsave(&b1->lock);
        if (idx1 != idx2)
            spin_lock(&b2->lock);
    } else {
        flags = spin_lock_irqsave(&b2->lock);
        spin_lock(&b1->lock);
    }

    u32 val;
    i64 rc = copy_from_user(&val, uaddr1, sizeof(val));
    if (rc < 0) {
        rc = -(i64) EFAULT;
        goto unlock;
    }
    if (val != expected) {
        rc = -(i64) EAGAIN;
        goto unlock;
    }

    struct futex_pi_state *dst_state =
        futex_pi_state_get_locked(b2, uaddr2, true);
    if (!dst_state) {
        rc = -(i64) EAGAIN;
        goto unlock;
    }

    u32 woken = 0;
    u32 requeued = 0;
    struct futex_waiter *w;
    dst_owner = dst_state->owner;
    list_for_each_entry_safe (&b1->waiters, w, struct futex_waiter, node) {
        if (w->key != uaddr1 || w->task->state != TD_STATE_BLOCKED)
            continue;
        if (woken < nr_wake) {
            list_del_init(&w->node);
            if (w->pi_wait) {
                futex_pi_clear_wait_dependency(w->task);
                if (w->pi_state) {
                    futex_pi_recompute_owner_locked(b1, w->pi_state);
                    src_owner = w->pi_state->owner;
                }
            }
            sched_wake_ready(w->task);
            woken++;
        } else if (requeued < nr_requeue) {
            list_del_init(&w->node);
            if (w->pi_wait) {
                futex_pi_clear_wait_dependency(w->task);
                if (w->pi_state) {
                    futex_pi_recompute_owner_locked(b1, w->pi_state);
                    src_owner = w->pi_state->owner;
                }
            }
            w->key = uaddr2;
            w->bucket = b2;
            w->pi_wait = true;
            w->pi_state = dst_state;
            if (dst_state->owner)
                futex_pi_set_wait_dependency(w->task, dst_state);
            list_add_tail(&b2->waiters, &w->node);
            requeued++;
        } else {
            break;
        }
    }

    futex_pi_recompute_owner_locked(b2, dst_state);
    rc = (i64) woken + (i64) requeued;

unlock:
    if (idx1 <= idx2) {
        if (idx1 != idx2)
            spin_unlock(&b2->lock);
        spin_unlock_irqrestore(&b1->lock, flags);
    } else {
        spin_unlock(&b1->lock);
        spin_unlock_irqrestore(&b2->lock, flags);
    }
    lockdep_release(LOCK_LEVEL_WAITQ);
    futex_pi_refresh_owner_chain(src_owner);
    futex_pi_refresh_owner_chain(dst_owner);
    return rc;
}

i64 futex_lock_pi(ptr uaddr)
{
    DEBUG_ASSERT(!in_interrupt_context());

    u32 idx = futex_hash(uaddr);
    struct futex_bucket *b = &futex_table[idx];

    struct futex_waiter w = {
        .key = uaddr,
        .task = sched_current_task(),
        .bucket = b,
        .pi_state = NULL,
        .pi_wait = true,
    };
    struct futex_cleanup_ctx cleanup = {
        .waiter = &w,
    };
    bool was_queued = false;
    list_init(&w.node);

    for (;;) {
        lockdep_acquire(LOCK_LEVEL_WAITQ);
        u64 flags = spin_lock_irqsave(&b->lock);

        i32 abort = wait_abort_error_current();
        if (abort < 0 && w.node.next != &w.node) {
            list_del_init(&w.node);
            struct sched_task *owner = NULL;
            if (w.pi_state)
                futex_pi_recompute_owner_locked(b, w.pi_state);
            if (w.pi_state)
                owner = w.pi_state->owner;
            futex_pi_clear_wait_dependency(w.task);
            sched_clear_block_cleanup(w.task);
            if (w.task->state == TD_STATE_BLOCKED)
                sched_set_task_state(w.task, TD_STATE_RUNNING);
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            futex_pi_refresh_owner_chain(owner);
            return (i64) abort;
        }

        u32 val;
        i64 rc = copy_from_user(&val, uaddr, sizeof(val));
        if (rc < 0) {
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i64) EFAULT;
        }

        u32 owner_tid = val & FUTEX_TID_MASK;
        u32 self_tid = (u32) sched_current_id();
        struct futex_pi_state *st = futex_pi_state_get_locked(b, uaddr, true);
        if (!st) {
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i64) EAGAIN;
        }
        w.pi_state = st;

        if (owner_tid == self_tid) {
            if (was_queued && st->owner == w.task) {
                futex_pi_clear_wait_dependency(w.task);
                sched_clear_block_cleanup(w.task);
                if (w.task->state == TD_STATE_BLOCKED)
                    sched_set_task_state(w.task, TD_STATE_RUNNING);
                spin_unlock_irqrestore(&b->lock, flags);
                lockdep_release(LOCK_LEVEL_WAITQ);
                return 0;
            }
            if (w.node.next != &w.node) {
                list_del_init(&w.node);
                futex_pi_recompute_owner_locked(b, st);
            }
            futex_pi_clear_wait_dependency(w.task);
            sched_clear_block_cleanup(w.task);
            if (w.task->state == TD_STATE_BLOCKED)
                sched_set_task_state(w.task, TD_STATE_RUNNING);
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i64) EDEADLK;
        }

        if (owner_tid == 0) {
            bool inherited_died = (val & FUTEX_OWNER_DIED) != 0;
            /* Preserve FUTEX_OWNER_DIED in the futex word so userspace
             * still sees the dead-owner marker; libc clears it via
             * pthread_mutex_consistent after recovering shared state.
             */
            u32 new_val = self_tid | (val & FUTEX_OWNER_DIED);
            rc = copy_to_user(uaddr, &new_val, sizeof(new_val));
            if (rc < 0) {
                spin_unlock_irqrestore(&b->lock, flags);
                lockdep_release(LOCK_LEVEL_WAITQ);
                return -(i64) EFAULT;
            }
            if (w.node.next != &w.node)
                list_del_init(&w.node);
            futex_pi_clear_wait_dependency(w.task);
            sched_clear_block_cleanup(w.task);
            if (w.task->state == TD_STATE_BLOCKED)
                sched_set_task_state(w.task, TD_STATE_RUNNING);
            st->owner_died = inherited_died;
            futex_pi_link_owner_locked(st, w.task);
            futex_pi_recompute_owner_locked(b, st);
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            /* POSIX robust-mutex contract: the previous owner died
             * holding the lock; tell userspace so it can run recovery
             * before the next pthread_mutex_lock returns success.
             */
            return inherited_died ? -(i64) EOWNERDEAD : 0;
        }

        if (!st->owner || st->owner->id != owner_tid)
            futex_pi_link_owner_locked(st, futex_find_task_by_tid(owner_tid));

        if (!st->owner) {
            u32 dead = FUTEX_OWNER_DIED;
            rc = copy_to_user(uaddr, &dead, sizeof(dead));
            if (rc < 0) {
                spin_unlock_irqrestore(&b->lock, flags);
                lockdep_release(LOCK_LEVEL_WAITQ);
                return -(i64) EFAULT;
            }
            st->owner_died = true;
            futex_pi_recompute_owner_locked(b, st);
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            continue;
        }

        futex_pi_set_wait_dependency(w.task, st);
        if (w.node.next == &w.node) {
            list_add_tail(&b->waiters, &w.node);
            was_queued = true;
        }
        futex_pi_recompute_owner_locked(b, st);
        struct sched_task *owner = st->owner;
        sched_set_task_state(w.task, TD_STATE_BLOCKED);
        sched_set_block_cleanup(w.task, futex_wait_cleanup, &cleanup);

        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        futex_pi_refresh_owner_chain(owner);
        sched_yield_trap();
    }
}

i64 futex_unlock_pi(ptr uaddr)
{
    u32 idx = futex_hash(uaddr);
    struct futex_bucket *b = &futex_table[idx];

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&b->lock);

    /* Verify caller owns the futex. */
    u32 val;
    i64 rc = copy_from_user(&val, uaddr, sizeof(val));
    if (rc < 0) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i64) EFAULT;
    }

    u32 tid = (u32) sched_current_id();
    if ((val & FUTEX_TID_MASK) != tid) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i64) EPERM;
    }

    struct futex_pi_state *st = futex_pi_state_get_locked(b, uaddr, false);
    if (st && st->owner && st->owner != sched_current_task()) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i64) EPERM;
    }

    struct sched_task *old_owner = sched_current_task();
    struct futex_waiter *best = NULL;
    if (st)
        futex_pi_refresh_waiters_locked(b, uaddr, &best);

    if (best) {
        u32 new_tid = (u32) best->task->id;
        i64 wr = copy_to_user(uaddr, &new_tid, sizeof(new_tid));
        if (wr < 0) {
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i64) EFAULT;
        }
        list_del_init(&best->node);
        futex_pi_clear_wait_dependency(best->task);
        if (st) {
            futex_pi_link_owner_locked(st, best->task);
            st->owner_died = false;
            futex_pi_recompute_owner_locked(b, st);
        }
        futex_pi_refresh_task_locked(old_owner);
        sched_wake_ready(best->task);
    } else {
        u32 zero = 0;
        i64 wr = copy_to_user(uaddr, &zero, sizeof(zero));
        if (wr < 0) {
            spin_unlock_irqrestore(&b->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i64) EFAULT;
        }
        if (st) {
            futex_pi_link_owner_locked(st, NULL);
            st->top_waiter_prio = 0;
            st->owner_died = false;
            futex_pi_state_maybe_free_locked(b, st);
        }
        futex_pi_refresh_task_locked(old_owner);
    }

    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    futex_pi_refresh_owner_chain(old_owner);
    return 0;
}

/* Walk the robust futex list of a dying process and unlock each entry.
 *
 * For each entry in the linked list:
 *   1. Compute the futex word address: entry_ptr + robust_futex_offset.
 *   2. Set FUTEX_OWNER_DIED in the futex word so the next acquirer
 *      knows the lock was orphaned and shared state may be inconsistent.
 *   3. Wake one waiter so a blocked task can acquire the orphaned futex.
 *
 * Also handles robust_pending (an entry being locked but not yet linked
 * into the list).
 *
 * Bounded to ROBUST_LIST_LIMIT iterations to prevent a corrupted user
 * list from wedging the kernel.
 */
#define ROBUST_LIST_LIMIT 2048

static void futex_handle_robust_entry(ptr entry, i32 futex_offset)
{
    /* Checked pointer arithmetic: reject overflow/underflow before
     * computing the futex address.  A corrupted user list could craft
     * entry + offset to wrap around and land on an unrelated address.
     * Unsigned arithmetic avoids signed-overflow UB on corrupted input.
     */
    uptr uentry = (uptr) entry;
    uptr futex_uaddr;
    if (futex_offset >= 0) {
        uptr off = (uptr) futex_offset;
        if (off > U64_MAX - uentry)
            return;
        futex_uaddr = uentry + off;
    } else {
        uptr off = (uptr) (-(i64) futex_offset);
        if (off > uentry)
            return;
        futex_uaddr = uentry - off;
    }
    ptr futex_addr = (ptr) futex_uaddr;

    /* Reject misaligned futex word -- u32 must be naturally aligned. */
    if ((uptr) futex_addr & (sizeof(u32) - 1))
        return;

    /* Validate the futex address before touching it. */
    if (!user_addr_writable(futex_addr, sizeof(u32)))
        return;

    u32 idx = futex_hash(futex_addr);
    struct futex_bucket *b = &futex_table[idx];

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&b->lock);

    u32 prev = 0;
    i64 prev_rc = copy_from_user(&prev, futex_addr, sizeof(prev));
    if (prev_rc < 0)
        prev = 0;
    struct futex_pi_state *st = futex_pi_state_get_locked(b, futex_addr, false);
    struct sched_task *old_owner = st ? st->owner : NULL;
    if (st) {
        futex_pi_link_owner_locked(st, NULL);
        st->owner_died = true;
        futex_pi_recompute_owner_locked(b, st);
        futex_pi_refresh_task_locked(old_owner);
    } else {
        old_owner = futex_find_task_by_tid(prev & FUTEX_TID_MASK);
    }

    u32 val = FUTEX_OWNER_DIED;
    i64 rc = copy_to_user(futex_addr, &val, sizeof(val));
    if (rc < 0) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return;
    }

    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    futex_pi_refresh_owner_chain(old_owner);

    futex_wake(futex_addr, 1);
}

/* Walk one thread's robust list and unlock its orphaned futexes,
 * then clear that thread's registration.  Snapshots the per-task
 * registration locally so the user-space walk runs without holding
 * any lock; copy_from_user can take a page fault and the kernel must
 * not be inside a spinlock or interrupts-disabled region when that
 * happens.
 */
void futex_exit_robust_list_task(struct sched_task *td)
{
    if (!td)
        return;

    ptr head, pending;
    i32 offset;

    /* Snapshot under proc_table_lock against concurrent writers. */
    u64 lflags = proc_table_lock_irqsave();
    head = td->td_robust_list_head;
    offset = td->td_robust_futex_offset;
    pending = td->td_robust_pending;
    /* Clear under the same lock so an SMP racer cannot see them. */
    td->td_robust_list_head = 0;
    td->td_robust_futex_offset = 0;
    td->td_robust_pending = 0;
    proc_table_unlock_irqrestore(lflags);

    /* Handle the pending entry first (may not be in the list). */
    if (pending != 0)
        futex_handle_robust_entry(pending, offset);

    if (head == 0)
        return;

    /* Walk the linked list.  Each entry's first sizeof(ptr) bytes
     * is a pointer to the next entry (like Linux robust_list.next).
     * The list is circular: terminates when we see the head again.
     */
    ptr entry = head;
    for (u32 i = 0; i < ROBUST_LIST_LIMIT; i++) {
        /* Read the next pointer from user space. */
        ptr next;
        i64 rc = copy_from_user(&next, entry, sizeof(next));
        if (rc < 0)
            break;

        /* Process this entry (skip if it was already handled as pending). */
        if (entry != head && entry != pending)
            futex_handle_robust_entry(entry, offset);

        entry = next;

        /* Circular list: stop when we return to the head. */
        if (entry == head)
            break;
    }
}

void futex_exit_robust_list(struct proc *p)
{
    if (!p)
        return;

    /* Snapshot the task pointer set under proc_table_lock, then
     * walk each task's list with the lock dropped. The tasks
     * themselves cannot be freed during this walk because proc_exit
     * is the sole detacher and proc_exit is the caller. The
     * structure scales with PROC_THREAD_MAX iterations.
     */
    struct sched_task *snap[PROC_THREAD_MAX];
    u64 flags = proc_table_lock_irqsave();
    for (u8 i = 0; i < PROC_THREAD_MAX; i++)
        snap[i] = p->tasks[i];
    proc_table_unlock_irqrestore(flags);

    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        if (snap[i])
            futex_exit_robust_list_task(snap[i]);
    }
}

static void futex_init_hook(u32 lifecycle_flag __unused)
{
    futex_init();
}
INIT_TASK("futex",
          futex_init_hook,
          INIT_REQUIRES(INITGRAPH_STAGE_SCHED),
          INIT_ENTAILS_NONE,
          INIT_FLAG_PRIMARY);

#include __INC_TEST(futex)
