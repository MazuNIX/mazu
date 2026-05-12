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
        return -(i32) EINVAL;
    if (len <= 0 || (usz) len > (usz) mq->max_msg_size)
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
        return -(i32) EINVAL;

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
        return -(i32) EINVAL;

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&mq->lock);
    u32 generation = mq->generation;

    if (!list_empty(&mq->msgs)) {
        i32 qidx = (i32) (mq - mq_pool);
        i32 ret = mqueue_do_receive(mq, qidx, buf, buf_size, out_priority);
        spin_unlock_irqrestore(&mq->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        return ret;
    }

    struct mq_waiter w = {
        .task = sched_current_task(),
        .generation = generation,
        .woken = false,
    };
    list_init(&w.node);
    list_add_tail(&mq->recv_waitq, &w.node);

    struct mq_timeout_ctx tctx = {
        .mq = mq,
        .waiter = &w,
        .timed_out = false,
    };
    struct callout tmo;
    callout_init(&tmo);
    struct mq_cleanup_ctx cleanup = {
        .mq = mq,
        .waiter = &w,
        .timeout_callout = &tmo,
    };
    callout_set_ticks(&tmo, time_ms_to_ticks(timeout.ms), mq_timeout_fn, &tctx);
    sched_set_task_state(w.task, TD_STATE_BLOCKED);
    sched_set_block_cleanup(w.task, mq_wait_cleanup, &cleanup);

    i32 abort = 0;
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

    i32 ret;
    if (abort < 0) {
        ret = abort;
    } else if (!mq->in_use || mq->generation != generation) {
        ret = -(i32) EBADF;
    } else if (w.woken && !list_empty(&mq->msgs)) {
        i32 qidx = (i32) (mq - mq_pool);
        ret = mqueue_do_receive(mq, qidx, buf, buf_size, out_priority);
    } else {
        ret = -(i32) ETIMEDOUT;
    }

    spin_unlock_irqrestore(&mq->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
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
