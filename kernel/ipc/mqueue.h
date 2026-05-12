/* SPDX-License-Identifier: MIT */
/* POSIX message queue for PSE51 inter-task messaging.
 *
 * Pool-allocated, bounded queues with priority ordering and blocking.
 * Higher-priority messages are dequeued first.
 *
 * Lock ordering: mq->lock (WAITQ) -> pcpu_runq_lock (SCHED).
 */

#ifndef MAZU_MQUEUE_H
#define MAZU_MQUEUE_H

#include <mazu/base.h>
#include <mazu/list.h>
#include <mazu/spinlock.h>
#include <mazu/time.h>

#define MQ_MAX_QUEUES 8
#define MQ_MAX_MSGS 16
#define MQ_MAX_MSG_SIZE 256

struct mq_msg {
    u8 data[MQ_MAX_MSG_SIZE];
    sz len;
    u32 priority;
    struct list_head node;
    bool in_use;
};

struct proc; /* forward declaration */

struct mqueue {
    spinlock_t lock;
    struct list_head msgs;       /* sorted by priority (highest first) */
    struct list_head send_waitq; /* tasks blocked on full queue */
    struct list_head recv_waitq; /* tasks blocked on empty queue */
    struct proc *owner;
    u32 owner_gen;
    u32 generation; /* increments each open to reject stale users */
    u32 msg_count;
    u32 max_msgs;
    sz max_msg_size;
    u32 refcount; /* cap_space slots referencing this queue */
    bool in_use;
};

/* Open/create a message queue.  Returns handle >= 0 or -errno. */
i32 mqueue_open(struct proc *owner, u32 max_msgs, sz max_msg_size);

/* Check if the caller owns this handle. */
bool mqueue_check_owner(i32 handle, struct proc *caller);

/* Close and release a message queue handle. Always tears the queue down,
 * waking any blocked senders/receivers with -EBADF. Used by the
 * pre-capability ABI and by sync_handle_teardown_proc.
 */
i32 mqueue_close(i32 handle);

/* Refcount-aware release: the underlying queue is destroyed only when the
 * last cap_space slot referencing it goes away. Used by the capability
 * layer in cap_release_object().
 */
void mqueue_put_idx(i32 handle);

/* Take an active-use reference on the queue. Returns true on success,
 * false if the slot is already torn down. Pairs with mqueue_put_idx().
 */
bool mqueue_inc_idx(i32 handle);

/* Send a message.  Blocks if queue is full.
 * Returns 0 on success, -EMSGSIZE if msg too large.
 */
i32 mqueue_send(i32 handle, const void *msg, sz len, u32 priority);

/* Receive the highest-priority message.  Blocks if queue is empty.
 * Returns message length on success, or -errno.
 */
i32 mqueue_receive(i32 handle, void *buf, sz buf_size, u32 *out_priority);

/* Receive with timeout.  Returns message length, -ETIMEDOUT, or -errno. */
i32 mqueue_timedreceive(i32 handle,
                        void *buf,
                        sz buf_size,
                        u32 *out_priority,
                        struct time_ms timeout);

#endif /* MAZU_MQUEUE_H */
