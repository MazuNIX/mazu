/* SPDX-License-Identifier: MIT */
/* POSIX message queue implementation.
 *
 * Pool-allocated fixed queues (max MQ_MAX_QUEUES). Messages stored in a
 * static pool per queue (max MQ_MAX_MSGS). Priority-ordered insertion:
 * higher priority messages dequeued first. Blocking send/receive via
 * waitqueue-style yield loops.
 */

#include "mqueue.h"
#include <mazu/assert.h>
#include <mazu/callout.h>
#include <mazu/eventlog.h>
#include <mazu/init.h>
#include <mazu/ipi.h>
#include <mazu/sched.h>
#include <mazu/spinlock.h>
#include "../lockdep.h"
#include "../proc/signal.h"

static struct mqueue mq_pool[MQ_MAX_QUEUES];
static struct mq_msg msg_pool[MQ_MAX_QUEUES][MQ_MAX_MSGS];
static spinlock_t mq_global_lock = SPINLOCK_INITIALIZER;

struct mq_waiter {
    struct sched_task *task;
    struct list_head node;
    u32 generation;
    bool woken;
};

struct mq_cleanup_ctx {
    struct mqueue *mq;
    struct mq_waiter *waiter;
    struct callout *timeout_callout;
};

static void mq_wait_cleanup(struct sched_task *task, void *ctx_ptr)
{
    struct mq_cleanup_ctx *ctx = ctx_ptr;
    assert(task);
    assert(ctx);

    if (ctx->timeout_callout)
        callout_cancel_sync(ctx->timeout_callout);

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&ctx->mq->lock);
    if (ctx->waiter->node.next != &ctx->waiter->node)
        list_del_init(&ctx->waiter->node);
    spin_unlock_irqrestore(&ctx->mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
}

static void mqueue_init_one(struct mqueue *mq)
{
    mq->lock = (spinlock_t) SPINLOCK_INITIALIZER;
    list_init(&mq->msgs);
    list_init(&mq->send_waitq);
    list_init(&mq->recv_waitq);
    mq->msg_count = 0;
    mq->in_use = false;
}

static void mqueue_reset_storage_locked(i32 qidx)
{
    struct mqueue *mq = &mq_pool[qidx];

    list_init(&mq->msgs);
    mq->msg_count = 0;
    for (i32 i = 0; i < MQ_MAX_MSGS; i++) {
        msg_pool[qidx][i].len = 0;
        msg_pool[qidx][i].priority = 0;
        msg_pool[qidx][i].in_use = false;
        list_init(&msg_pool[qidx][i].node);
    }
}

i32 mqueue_open(struct proc *owner, u32 max_msgs, sz max_msg_size)
{
    if (max_msgs == 0 || max_msgs > MQ_MAX_MSGS)
        return -(i32) EINVAL;
    if (max_msg_size == 0 || max_msg_size > MQ_MAX_MSG_SIZE)
        return -(i32) EINVAL;

    u64 flags = spin_lock_irqsave(&mq_global_lock);
    for (i32 i = 0; i < MQ_MAX_QUEUES; i++) {
        if (!mq_pool[i].in_use) {
            u32 next_generation = mq_pool[i].generation + 1;
            if (next_generation == 0)
                next_generation = 1;
            mqueue_init_one(&mq_pool[i]);
            mq_pool[i].in_use = true;
            mq_pool[i].owner = owner;
            mq_pool[i].owner_gen = owner ? owner->generation : 0;
            mq_pool[i].generation = next_generation;
            mq_pool[i].max_msgs = max_msgs;
            mq_pool[i].max_msg_size = max_msg_size;
            mq_pool[i].refcount = 1;
            spin_unlock_irqrestore(&mq_global_lock, flags);
            return i;
        }
    }
    spin_unlock_irqrestore(&mq_global_lock, flags);
    return -(i32) EAGAIN;
}

/* Tear down the queue's wait state and mark it free. Caller must hold
 * mq_global_lock for the in_use transition; this helper acquires the
 * per-queue lock to drain waiters.
 */
static void mqueue_destroy_locked(i32 handle)
{
    struct mqueue *mq = &mq_pool[handle];

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    mq->in_use = false;
    mq->refcount = 0;
    mqueue_reset_storage_locked(handle);

    while (!list_empty(&mq->recv_waitq)) {
        struct mq_waiter *w =
            list_entry(mq->recv_waitq.next, struct mq_waiter, node);
        list_del_init(&w->node);
        w->woken = true;
        sched_wake_ready(w->task);
    }
    while (!list_empty(&mq->send_waitq)) {
        struct mq_waiter *w =
            list_entry(mq->send_waitq.next, struct mq_waiter, node);
        list_del_init(&w->node);
        w->woken = true;
        sched_wake_ready(w->task);
    }

    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
}

i32 mqueue_close(i32 handle)
{
    if (handle < 0 || handle >= MQ_MAX_QUEUES)
        return -(i32) EBADF;

    struct mqueue *mq = &mq_pool[handle];
    u64 gflags = spin_lock_irqsave(&mq_global_lock);
    if (!mq->in_use) {
        spin_unlock_irqrestore(&mq_global_lock, gflags);
        return -(i32) EBADF;
    }

    mqueue_destroy_locked(handle);
    spin_unlock_irqrestore(&mq_global_lock, gflags);
    return 0;
}

void mqueue_put_idx(i32 handle)
{
    if (handle < 0 || handle >= MQ_MAX_QUEUES)
        return;

    struct mqueue *mq = &mq_pool[handle];
    u64 gflags = spin_lock_irqsave(&mq_global_lock);
    if (!mq->in_use) {
        spin_unlock_irqrestore(&mq_global_lock, gflags);
        return;
    }
    if (mq->refcount > 1) {
        mq->refcount--;
        spin_unlock_irqrestore(&mq_global_lock, gflags);
        return;
    }
    mqueue_destroy_locked(handle);
    spin_unlock_irqrestore(&mq_global_lock, gflags);
}

bool mqueue_inc_idx(i32 handle)
{
    if (handle < 0 || handle >= MQ_MAX_QUEUES)
        return false;

    struct mqueue *mq = &mq_pool[handle];
    u64 gflags = spin_lock_irqsave(&mq_global_lock);
    if (!mq->in_use) {
        spin_unlock_irqrestore(&mq_global_lock, gflags);
        return false;
    }
    mq->refcount++;
    spin_unlock_irqrestore(&mq_global_lock, gflags);
    return true;
}

static struct mqueue *mqueue_get(i32 handle)
{
    if (handle < 0 || handle >= MQ_MAX_QUEUES)
        return NULL;
    if (!mq_pool[handle].in_use)
        return NULL;
    return &mq_pool[handle];
}

sz mqueue_get_msgsize(i32 handle)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(sz) 1;
    return (sz) mq->max_msg_size;
}

bool mqueue_check_owner(i32 handle, struct proc *caller)
{
    if (handle < 0 || handle >= MQ_MAX_QUEUES)
        return false;
    struct mqueue *mq = &mq_pool[handle];
    if (!mq->in_use)
        return false;
    /* NULL owner matches NULL caller (kernel tasks). */
    if (!mq->owner && !caller)
        return true;
    return mq->owner == caller && caller && mq->owner_gen == caller->generation;
}

/* Find a free message slot for the given queue index. */
static struct mq_msg *msg_alloc(i32 qidx)
{
    for (i32 i = 0; i < MQ_MAX_MSGS; i++) {
        if (!msg_pool[qidx][i].in_use)
            return &msg_pool[qidx][i];
    }
    return NULL;
}

/* Insert a message in priority order (highest first). */
static void msg_insert_priority(struct mqueue *mq, struct mq_msg *msg)
{
    struct list_head *pos = mq->msgs.next;
    while (pos != &mq->msgs) {
        struct mq_msg *cur = list_entry(pos, struct mq_msg, node);
        if (msg->priority > cur->priority) {
            /* Insert before this lower-priority message. */
            list_add(pos->prev, &msg->node);
            return;
        }
        pos = pos->next;
    }
    /* Lowest priority: append at tail. */
    list_add_tail(&mq->msgs, &msg->node);
}

static void wake_one(struct list_head *waitq)
{
    if (list_empty(waitq))
        return;
    struct mq_waiter *w = list_entry(waitq->next, struct mq_waiter, node);
    list_del_init(&w->node);
    w->woken = true;
    sched_wake_ready(w->task);
}

i32 mqueue_send(i32 handle, const void *msg, sz len, u32 priority)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(i32) EBADF;
    /* POSIX permits zero-length messages; only oversized payloads fail. */
    if (len < 0 || (usz) len > (usz) mq->max_msg_size)
        return -(i32) EMSGSIZE;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    u32 generation = mq->generation;

    /* Block until space available, queue closed, or signal pending. */
    while (mq->msg_count >= mq->max_msgs) {
        if (!mq->in_use || mq->generation != generation) {
            spin_unlock_irqrestore(&mq->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i32) EBADF;
        }
        i32 abort = wait_abort_error_current();
        if (abort < 0) {
            spin_unlock_irqrestore(&mq->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return abort;
        }
        struct mq_waiter w = {
            .task = sched_current_task(),
            .generation = generation,
            .woken = false,
        };
        struct mq_cleanup_ctx cleanup = {
            .mq = mq,
            .waiter = &w,
            .timeout_callout = NULL,
        };
        list_init(&w.node);
        list_add_tail(&mq->send_waitq, &w.node);
        sched_set_task_state(w.task, TD_STATE_BLOCKED);
        sched_set_block_cleanup(w.task, mq_wait_cleanup, &cleanup);

        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        sched_yield_trap();
        lockdep_acquire(LOCK_LEVEL_WAITQ);
        flags = spin_lock_irqsave(&mq->lock);

        list_del_init(&w.node);
        sched_clear_block_cleanup(w.task);
        if (w.task->state == TD_STATE_BLOCKED)
            sched_set_task_state(w.task, TD_STATE_RUNNING);
    }

    i32 qidx = (i32) (mq - mq_pool);
    struct mq_msg *slot = msg_alloc(qidx);
    if (!slot) {
        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i32) ENOMEM;
    }

    /* Copy message data. */
    for (sz i = 0; i < len; i++)
        slot->data[i] = ((const u8 *) msg)[i];
    slot->len = len;
    slot->priority = priority;
    slot->in_use = true;
    list_init(&slot->node);
    msg_insert_priority(mq, slot);
    mq->msg_count++;

    /* Wake a blocked receiver. */
    wake_one(&mq->recv_waitq);

    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return 0;
}

i32 mqueue_trysend(i32 handle, const void *msg, sz len, u32 priority)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(i32) EBADF;
    if (len < 0 || (usz) len > (usz) mq->max_msg_size)
        return -(i32) EMSGSIZE;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    if (mq->msg_count >= mq->max_msgs) {
        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i32) EAGAIN;
    }

    i32 qidx = (i32) (mq - mq_pool);
    struct mq_msg *slot = msg_alloc(qidx);
    if (!slot) {
        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i32) ENOMEM;
    }

    for (sz i = 0; i < len; i++)
        slot->data[i] = ((const u8 *) msg)[i];
    slot->len = len;
    slot->priority = priority;
    slot->in_use = true;
    list_init(&slot->node);
    msg_insert_priority(mq, slot);
    mq->msg_count++;
    wake_one(&mq->recv_waitq);

    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return 0;
}

struct mq_send_timeout_ctx {
    struct mqueue *mq;
    struct mq_waiter *waiter;
    volatile bool timed_out;
};

static void mq_send_timeout_fn(void *arg)
{
    struct mq_send_timeout_ctx *ctx = arg;
    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&ctx->mq->lock);

    if (ctx->waiter->node.next != &ctx->waiter->node && !ctx->waiter->woken &&
        ctx->waiter->task->state != TD_STATE_TERMINATING) {
        list_del_init(&ctx->waiter->node);
        ctx->timed_out = true;
        sched_wake_ready(ctx->waiter->task);
    }

    spin_unlock_irqrestore(&ctx->mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
}

i32 mqueue_timedsend(i32 handle,
                     const void *msg,
                     sz len,
                     u32 priority,
                     struct time_ms timeout)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(i32) EBADF;
    if (len < 0 || (usz) len > (usz) mq->max_msg_size)
        return -(i32) EMSGSIZE;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    u32 generation = mq->generation;
    bool waited = false;
    i32 abort = 0;
    i32 ret = 0;
    struct callout tmo;
    struct mq_waiter w;
    struct mq_send_timeout_ctx tctx;
    struct mq_cleanup_ctx cleanup;

    if (mq->msg_count >= mq->max_msgs) {
        waited = true;
        w = (struct mq_waiter) {
            .task = sched_current_task(),
            .generation = generation,
            .woken = false,
        };
        list_init(&w.node);
        tctx = (struct mq_send_timeout_ctx) {
            .mq = mq,
            .waiter = &w,
            .timed_out = false,
        };
        callout_init(&tmo);
        cleanup = (struct mq_cleanup_ctx) {
            .mq = mq,
            .waiter = &w,
            .timeout_callout = &tmo,
        };
        callout_set_ticks(&tmo, time_ms_to_ticks(timeout.ms),
                          mq_send_timeout_fn, &tctx);

        while (mq->msg_count >= mq->max_msgs) {
            if (!mq->in_use || mq->generation != generation) {
                ret = -(i32) EBADF;
                goto out_wait;
            }

            if (w.node.next == &w.node) {
                w.woken = false;
                list_add_tail(&mq->send_waitq, &w.node);
                sched_set_task_state(w.task, TD_STATE_BLOCKED);
                sched_set_block_cleanup(w.task, mq_wait_cleanup, &cleanup);
            }

            while (!w.woken && !tctx.timed_out) {
                abort = wait_abort_error_current();
                if (abort < 0)
                    break;
                spin_unlock_irqrestore(&mq->lock, flags);
                lockdep_release(LOCK_LEVEL_WAITQ);
                sched_yield_trap();
                lockdep_acquire(LOCK_LEVEL_WAITQ);
                flags = spin_lock_irqsave(&mq->lock);
            }

            list_del_init(&w.node);
            sched_clear_block_cleanup(w.task);
            if (w.task->state == TD_STATE_BLOCKED)
                sched_set_task_state(w.task, TD_STATE_RUNNING);

            /* Real receiver wake takes precedence over a racing clock-settime
             * restart: if a wake_one already moved this sender out of the
             * waitq, honor it and fall through to enqueue rather than letting
             * the syscall retry drop the slot to a later sender.
             */
            if (abort < 0 && !w.woken) {
                ret = abort;
                goto out_wait;
            }
            if (tctx.timed_out && !w.woken) {
                ret = -(i32) ETIMEDOUT;
                goto out_wait;
            }
            abort = 0;
        }
    }

    /* The waiter may have been released by mqueue_destroy_locked, which
     * zeroes msg_count before draining send_waitq; the outer while then
     * exits without entering the in-loop EBADF check.  Re-validate the
     * queue is still the same generation and still in use before touching
     * msg_pool, otherwise the sender would silently enqueue into a freed
     * slot pool that may have been reopened by another owner.
     */
    if (!mq->in_use || mq->generation != generation) {
        ret = -(i32) EBADF;
        goto out_wait;
    }

    i32 qidx = (i32) (mq - mq_pool);
    struct mq_msg *slot = msg_alloc(qidx);
    if (!slot) {
        ret = -(i32) ENOMEM;
        goto out_wait;
    }

    for (sz i = 0; i < len; i++)
        slot->data[i] = ((const u8 *) msg)[i];
    slot->len = len;
    slot->priority = priority;
    slot->in_use = true;
    list_init(&slot->node);
    msg_insert_priority(mq, slot);
    mq->msg_count++;
    wake_one(&mq->recv_waitq);

out_wait:
    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    if (waited)
        callout_cancel_sync(&tmo);
    return ret;
}

/* Internal receive: dequeue highest-priority message. */
static i32 mqueue_do_receive(struct mqueue *mq,
                             i32 qidx __unused,
                             void *buf,
                             sz buf_size,
                             u32 *out_priority)
{
    struct mq_msg *msg = list_entry(mq->msgs.next, struct mq_msg, node);
    if ((usz) msg->len > (usz) buf_size) {
        return -(i32) EMSGSIZE;
    }

    list_del_init(&msg->node);
    mq->msg_count--;

    i32 ret = (i32) msg->len;
    for (sz i = 0; i < msg->len; i++)
        ((u8 *) buf)[i] = msg->data[i];
    if (out_priority)
        *out_priority = msg->priority;

    /* Reset slot for reuse. */
    msg->len = 0;
    msg->priority = 0;
    msg->in_use = false;

    /* Wake a blocked sender. */
    wake_one(&mq->send_waitq);

    return ret;
}

i32 mqueue_receive(i32 handle, void *buf, sz buf_size, u32 *out_priority)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(i32) EBADF;
    /* Per-message size check happens inside mqueue_do_receive.  The strict
     * POSIX "buf_size >= mq_msgsize" rule lives at the syscall boundary
     * (mq_receive_common) so kernel-internal callers can dequeue into
     * smaller scratch buffers when they know the message size.
     */
    if (buf_size < 0)
        return -(i32) EMSGSIZE;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    u32 generation = mq->generation;

    /* Block until message available, queue closed, or signal pending. */
    while (list_empty(&mq->msgs)) {
        if (!mq->in_use || mq->generation != generation) {
            spin_unlock_irqrestore(&mq->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return -(i32) EBADF;
        }
        i32 abort = wait_abort_error_current();
        if (abort < 0) {
            spin_unlock_irqrestore(&mq->lock, flags);
            lockdep_release(LOCK_LEVEL_WAITQ);
            return abort;
        }
        struct mq_waiter w = {
            .task = sched_current_task(),
            .generation = generation,
            .woken = false,
        };
        struct mq_cleanup_ctx cleanup = {
            .mq = mq,
            .waiter = &w,
            .timeout_callout = NULL,
        };
        list_init(&w.node);
        list_add_tail(&mq->recv_waitq, &w.node);
        sched_set_task_state(w.task, TD_STATE_BLOCKED);
        sched_set_block_cleanup(w.task, mq_wait_cleanup, &cleanup);

        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        sched_yield_trap();
        lockdep_acquire(LOCK_LEVEL_WAITQ);
        flags = spin_lock_irqsave(&mq->lock);

        list_del_init(&w.node);
        sched_clear_block_cleanup(w.task);
        if (w.task->state == TD_STATE_BLOCKED)
            sched_set_task_state(w.task, TD_STATE_RUNNING);
    }

    i32 qidx = (i32) (mq - mq_pool);
    i32 ret = mqueue_do_receive(mq, qidx, buf, buf_size, out_priority);

    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return ret;
}

i32 mqueue_tryreceive(i32 handle, void *buf, sz buf_size, u32 *out_priority)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(i32) EBADF;
    if (buf_size < 0)
        return -(i32) EMSGSIZE;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    if (list_empty(&mq->msgs)) {
        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return -(i32) EAGAIN;
    }

    i32 ret = mqueue_do_receive(mq, handle, buf, buf_size, out_priority);
    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    return ret;
}

/* Timed receive timeout callback. */
struct mq_timeout_ctx {
    struct mqueue *mq;
    struct mq_waiter *waiter;
    bool timed_out;
};

static void mq_timeout_fn(void *arg)
{
    struct mq_timeout_ctx *ctx = arg;
    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&ctx->mq->lock);

    if (ctx->waiter->node.next != &ctx->waiter->node && !ctx->waiter->woken &&
        ctx->waiter->task->state != TD_STATE_TERMINATING) {
        list_del_init(&ctx->waiter->node);
        ctx->timed_out = true;
        sched_wake_ready(ctx->waiter->task);
    }

    spin_unlock_irqrestore(&ctx->mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
}

i32 mqueue_timedreceive(i32 handle,
                        void *buf,
                        sz buf_size,
                        u32 *out_priority,
                        struct time_ms timeout)
{
    struct mqueue *mq = mqueue_get(handle);
    if (!mq)
        return -(i32) EBADF;
    if (buf_size < 0)
        return -(i32) EMSGSIZE;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    u32 generation = mq->generation;
    bool waited = false;
    i32 abort = 0;
    i32 ret = 0;
    struct callout tmo;
    struct mq_waiter w;
    struct mq_timeout_ctx tctx;
    struct mq_cleanup_ctx cleanup;

    if (list_empty(&mq->msgs)) {
        waited = true;
        w = (struct mq_waiter) {
            .task = sched_current_task(),
            .generation = generation,
            .woken = false,
        };
        list_init(&w.node);
        tctx = (struct mq_timeout_ctx) {
            .mq = mq,
            .waiter = &w,
            .timed_out = false,
        };
        callout_init(&tmo);
        cleanup = (struct mq_cleanup_ctx) {
            .mq = mq,
            .waiter = &w,
            .timeout_callout = &tmo,
        };
        callout_set_ticks(&tmo, time_ms_to_ticks(timeout.ms), mq_timeout_fn,
                          &tctx);

        while (list_empty(&mq->msgs)) {
            if (!mq->in_use || mq->generation != generation) {
                ret = -(i32) EBADF;
                goto out_wait;
            }

            if (w.node.next == &w.node) {
                w.woken = false;
                list_add_tail(&mq->recv_waitq, &w.node);
                sched_set_task_state(w.task, TD_STATE_BLOCKED);
                sched_set_block_cleanup(w.task, mq_wait_cleanup, &cleanup);
            }

            while (!w.woken && !tctx.timed_out) {
                abort = wait_abort_error_current();
                if (abort < 0)
                    break;
                spin_unlock_irqrestore(&mq->lock, flags);
                lockdep_release(LOCK_LEVEL_WAITQ);
                sched_yield_trap();
                lockdep_acquire(LOCK_LEVEL_WAITQ);
                flags = spin_lock_irqsave(&mq->lock);
            }

            list_del_init(&w.node);
            sched_clear_block_cleanup(w.task);
            if (w.task->state == TD_STATE_BLOCKED)
                sched_set_task_state(w.task, TD_STATE_RUNNING);

            /* A real sender wake (wake_one set w.woken) takes precedence over
             * a clock-settime restart that races it.  Without this gate, the
             * waiter would return MAZU_WAIT_ABORT_CLOCK_SETTIME and the
             * syscall retry could lose the message to a later receiver.
             */
            if (abort < 0 && !w.woken) {
                ret = abort;
                goto out_wait;
            }
            if (tctx.timed_out && !w.woken) {
                ret = -(i32) ETIMEDOUT;
                goto out_wait;
            }
            abort = 0;
        }
    }

    /* mqueue_destroy_locked clears msg storage then wakes receivers; on
     * wake the outer while exits because list_empty is true.  Without the
     * post-loop check we would dequeue from a freed queue.  Also covers
     * the case where a concurrent racer drained the queue between our
     * wake and our reacquire of mq->lock.
     */
    if (!mq->in_use || mq->generation != generation) {
        ret = -(i32) EBADF;
        goto out_wait;
    }
    if (list_empty(&mq->msgs)) {
        ret = -(i32) ETIMEDOUT;
        goto out_wait;
    }

    {
        i32 qidx = (i32) (mq - mq_pool);
        ret = mqueue_do_receive(mq, qidx, buf, buf_size, out_priority);
    }

out_wait:
    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    if (waited)
        callout_cancel_sync(&tmo);
    return ret;
}

static void mqueue_boot_init(u32 flag __unused)
{
    for (i32 i = 0; i < MQ_MAX_QUEUES; i++) {
        mqueue_init_one(&mq_pool[i]);
        for (i32 j = 0; j < MQ_MAX_MSGS; j++) {
            msg_pool[i][j].len = 0;
            msg_pool[i][j].in_use = false;
            list_init(&msg_pool[i][j].node);
        }
    }
}
DEFINE_INIT_HOOK(mqueue_boot_init, INIT_LEVEL_SUBSYS, INIT_FLAG_PRIMARY);

#include __INC_TEST(mqueue)
