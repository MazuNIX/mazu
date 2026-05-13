/* SPDX-License-Identifier: MIT */
/* Futex: fast userspace mutual exclusion.
 *
 * Hash-table of wait queues keyed by user virtual address.
 * FUTEX_WAIT atomically checks the user word and blocks;
 * FUTEX_WAKE wakes waiters on the same address.
 *
 * PI futexes maintain explicit owner state in the kernel so contended
 * FUTEX_LOCK_PI can donate priority to the current owner, unlock can
 * hand ownership directly to the highest-priority waiter, robust exit
 * can clear stale donation on owner death, and FUTEX_CMP_REQUEUE_PI
 * can move condvar-style waiters onto the destination mutex while
 * preserving PI donation.
 *
 * Lock ordering: futex bucket lock (WAITQ) -> pcpu_runq_lock (SCHED).
 */

#ifndef MAZU_FUTEX_H
#define MAZU_FUTEX_H

#include <mazu/base.h>

struct proc;
struct sched_task;
struct futex_pi_state;

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_CMP_REQUEUE 2
#define FUTEX_LOCK_PI 3
#define FUTEX_UNLOCK_PI 4
#define FUTEX_CMP_REQUEUE_PI 5

/* Initialize the futex hash table.  Called once at boot. */
void futex_init(void);

/* FUTEX_WAIT: if *uaddr == expected, block until woken.
 * Returns 0 on wake, -EAGAIN if value mismatch, -EFAULT on bad pointer.
 */
i64 futex_wait(ptr uaddr, u32 expected);

/* FUTEX_WAKE: wake up to max_wake waiters blocked on uaddr.
 * Returns number of tasks woken.
 */
i64 futex_wake(ptr uaddr, u32 max_wake);

/* FUTEX_CMP_REQUEUE: atomically wake up to nr_wake waiters on uaddr1,
 * then move up to nr_requeue remaining waiters from uaddr1 to uaddr2.
 * The operation aborts with -EAGAIN if *uaddr1 != expected.
 * Returns total number of woken + requeued tasks.
 */
i64 futex_cmp_requeue(ptr uaddr1,
                      u32 expected,
                      ptr uaddr2,
                      u32 nr_wake,
                      u32 nr_requeue);

/* FUTEX_CMP_REQUEUE_PI: wake up to nr_wake waiters on uaddr1, then move
 * up to nr_requeue remaining waiters from uaddr1 to uaddr2 while preserving
 * PI donation toward uaddr2's current owner when one exists.
 */
i64 futex_cmp_requeue_pi(ptr uaddr1,
                         u32 expected,
                         ptr uaddr2,
                         u32 nr_wake,
                         u32 nr_requeue);

/* FUTEX_LOCK_PI: acquire PI-aware futex.  Blocks if the futex is held
 * by another task, donates waiter priority to the owner while queued,
 * and preserves FUTEX_OWNER_DIED in the futex word when a robust-exit
 * handoff left recovery state for user space to observe.
 * Returns 0 on acquisition, -EOWNERDEAD when the previous owner died
 * holding the lock (caller now owns it but the protected state is
 * presumed inconsistent until pthread_mutex_consistent runs), -EFAULT
 * on bad pointer.
 */
i64 futex_lock_pi(ptr uaddr);

/* FUTEX_UNLOCK_PI: release PI-aware futex and wake highest-priority waiter.
 * Returns 0 on success, -EFAULT on bad pointer, -EPERM if not owner.
 */
i64 futex_unlock_pi(ptr uaddr);

/* Refresh the cached top waiter priority for a contended PI futex and return
 * its current owner so transitive donation can continue upstream.
 */
struct sched_task *futex_pi_refresh_wait_chain(struct futex_pi_state *st);

/* Walk the robust futex list of a dying process and unlock orphaned
 * futexes.  Called from the process exit path.  Writes
 * FUTEX_OWNER_DIED to each futex word, drops any stale PI donation,
 * and wakes one waiter per entry.
 */
void futex_exit_robust_list(struct proc *p);

/* Walk one thread's robust futex list and clear its registration.
 * Used by SYS_THREAD_EXIT for non-last-thread exits, where the
 * dying thread must release its own held futexes without tearing
 * down the rest of the process.
 */
void futex_exit_robust_list_task(struct sched_task *td);

#endif /* MAZU_FUTEX_H */
