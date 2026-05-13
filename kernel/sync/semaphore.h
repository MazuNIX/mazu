/* SPDX-License-Identifier: MIT */
/* Counting semaphore with direct-handover wake policy.
 *
 * sem_post() passes the token directly to the first blocked waiter;
 * the counter only grows when no waiters exist.  This ensures
 * deterministic wake latency (STK-inspired).
 *
 * Semaphores have no owner concept, so they do not participate in
 * priority inheritance. Use pi_mutex for owner-sensitive RT critical
 * sections where inversion bounds matter.
 *
 * Lock ordering: sem->lock (WAITQ) -> pcpu_runq_lock (SCHED).
 */

#ifndef MAZU_SEMAPHORE_H
#define MAZU_SEMAPHORE_H

#include <mazu/list.h>
#include <mazu/spinlock.h>
#include <mazu/time.h>

struct semaphore {
    spinlock_t lock;
    i32 count;                /* available tokens (>= 0 when no waiters) */
    struct list_head waiters; /* list of sem_waiter, FIFO order */
};

void sem_init(struct semaphore *sem, i32 initial_count);

/* Acquire a token, blocking if count is zero. */
void sem_wait(struct semaphore *sem);

/* Like sem_wait, but returns -EINTR if a signal becomes pending. */
i32 sem_wait_interruptible(struct semaphore *sem);

/* Try to acquire without blocking.  Returns 0 on success, -EAGAIN if empty. */
i32 sem_trywait(struct semaphore *sem);

/* Release a token.  If waiters exist, hands token directly to the
 * first waiter (counter stays at 0).  Otherwise increments count.
 */
void sem_post(struct semaphore *sem);

/* Acquire a token with timeout.  Returns 0 on success, -ETIMEDOUT
 * if the timeout expires before a token becomes available.
 */
i32 sem_timedwait(struct semaphore *sem, struct time_ms timeout);

#endif /* MAZU_SEMAPHORE_H */
