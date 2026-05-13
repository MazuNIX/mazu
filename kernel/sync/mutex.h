/* SPDX-License-Identifier: MIT */
/* Priority-inheriting mutex.
 *
 * When a high-priority task blocks on a mutex held by a low-priority task, the
 * owner's priority is temporarily boosted to the highest waiter's priority to
 * prevent priority inversion. On unlock, the owner's effective priority is
 * recomputed from all remaining held PI mutexes (falls back to td_base_prio
 * when no other PI mutexes are held).  Ownership is transferred via direct
 * handover, with no barging window.
 *
 * PI propagation walks bounded wait chains so donation and deboost can travel
 * across nested mutex and futex dependencies.
 *
 * Lock ordering: mutex->lock (WAITQ) -> pcpu_runq_lock (SCHED).
 */

#ifndef MAZU_MUTEX_H
#define MAZU_MUTEX_H

#include <mazu/list.h>
#include <mazu/sched.h>
#include <mazu/spinlock.h>
#include <mazu/time.h>

struct pi_mutex {
    spinlock_t lock;
    struct sched_task *owner; /* current holder, or NULL */
    struct list_head waiters; /* list of pi_mutex_waiter, priority-ordered */
    struct list_head pi_held; /* links into owner's pi_held_mutexes chain */
    u8 top_waiter_prio;       /* cached prio of highest waiter (0 if none) */
};

void pi_mutex_init(struct pi_mutex *mtx);

/* Acquire the mutex, blocking if held by another task.
 * May boost the owner's priority (priority inheritance).
 */
void pi_mutex_lock(struct pi_mutex *mtx);

/* Like pi_mutex_lock but returns -EINTR if a signal interrupts the wait. */
i32 pi_mutex_lock_interruptible(struct pi_mutex *mtx);

/* Like pi_mutex_lock_interruptible but bounds the wait. */
i32 pi_mutex_lock_timed(struct pi_mutex *mtx, struct time_ms timeout);

/* Try to acquire the mutex without blocking.
 * Returns 0 on success, -EBUSY if already held.
 */
i32 pi_mutex_trylock(struct pi_mutex *mtx);

/* Release the mutex.  Recomputes the caller's priority from any remaining held
 * PI mutexes and wakes the highest-priority waiter via direct handover
 * (ownership transfer under the lock).
 */
void pi_mutex_unlock(struct pi_mutex *mtx);

/* Recompute a task's effective priority from td_base_prio and any PI boosts
 * implied by mutexes it currently holds.
 */
void pi_mutex_refresh_prio(struct sched_task *task);

/* Recompute only the task-local effective priority. Callers that already hold
 * another PI object's lock use this form, then continue any upstream chain
 * refresh after dropping that lock.
 */
void pi_mutex_refresh_prio_local(struct sched_task *task);

/* Refresh the cached top waiter priority for a contended PI mutex and return
 * its current owner so transitive donation can continue upstream.
 */
struct sched_task *pi_mutex_refresh_wait_chain(struct pi_mutex *mtx);

/* Force-release every PI mutex still owned by a task that is being destroyed.
 * Waiters receive the same direct handover/wake policy as a normal unlock.
 */
void pi_mutex_release_all(struct sched_task *task);

/* Acquire/release the per-task PI lock that serializes all access to
 * pi_held_mutexes, pi_held_futexes, and the derived priority fields.
 * Always taken as the innermost lock (LOCK_LEVEL_NONE).
 */
static inline u64 task_pi_lock(struct sched_task *t)
{
    return spin_lock_irqsave(&t->td_pi_lock);
}

static inline void task_pi_unlock(struct sched_task *t, u64 flags)
{
    spin_unlock_irqrestore(&t->td_pi_lock, flags);
}

#endif /* MAZU_MUTEX_H */
