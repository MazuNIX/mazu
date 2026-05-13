/* SPDX-License-Identifier: MIT */
/* PI mutex self-tests.
 *
 * Test 1: uncontended lock/unlock.
 * Test 2: trylock succeeds when free, fails when held.
 * Test 3: priority inheritance, low-priority holder is boosted.
 * Test 4: two tasks contend; correct count via mutex.
 * Test 5: multi-mutex priority recomputation, unlocking one mutex
 *          retains boost from another mutex's waiters.
 */

#include <kernel/sync/mutex.h>
#include "tests-common.h"
#include "tests-proc-helpers.h"

/* Test 1: basic uncontended lock/unlock cycle. */
static i32 test_mutex_basic(void)
{
    struct pi_mutex mtx;
    pi_mutex_init(&mtx);

    pi_mutex_lock(&mtx);
    if (mtx.owner != sched_current_task()) {
        pi_mutex_unlock(&mtx);
        return 1;
    }

    pi_mutex_unlock(&mtx);
    SELFTEST_ASSERT(mtx.owner == NULL, 2);

    return 0;
}
DEFINE_SELFTEST(mutex_basic, test_mutex_basic);

/* Test 2: trylock semantics. */
static i32 test_mutex_trylock(void)
{
    struct pi_mutex mtx;
    pi_mutex_init(&mtx);

    if (pi_mutex_trylock(&mtx) != 0)
        return 1;

    /* Second trylock must fail (held by self). */
    if (pi_mutex_trylock(&mtx) != -(i32) EBUSY) {
        pi_mutex_unlock(&mtx);
        return 2;
    }

    pi_mutex_unlock(&mtx);
    return 0;
}
DEFINE_SELFTEST(mutex_trylock, test_mutex_trylock);

/* Test 3: priority inheritance, low-priority holder is boosted. */
static struct pi_mutex pi_test_mtx;
static volatile bool pi_test_holder_locked;
static volatile bool pi_test_holder_boosted;
static volatile bool pi_test_done;

static void pi_test_low_prio_holder(void *ctx __unused)
{
    pi_mutex_lock(&pi_test_mtx);
    pi_test_holder_locked = true;

    /* Let the high-priority task run and contend. */
    SELFTEST_KICK_AND_YIELD(80);

    /* Check if the priority was boosted above NORMAL. */
    struct sched_task *self = sched_current_task();
    pi_test_holder_boosted = (self->td_prio > SCHED_PRIO_NORMAL);

    pi_mutex_unlock(&pi_test_mtx);
}

static void pi_test_high_prio_waiter(void *ctx __unused)
{
    /* Wait until the holder has acquired the mutex. */
    while (!pi_test_holder_locked)
        SELFTEST_KICK_AND_YIELD(10);

    /* This will block and trigger PI boost on the holder. */
    pi_mutex_lock(&pi_test_mtx);
    pi_mutex_unlock(&pi_test_mtx);

    pi_test_done = true;
}

static i32 test_mutex_priority_inheritance(void)
{
    pi_mutex_init(&pi_test_mtx);
    pi_test_holder_locked = false;
    pi_test_holder_boosted = false;
    pi_test_done = false;

    struct result r;
    r = sched_create_task_prio(pi_test_low_prio_holder, NULL,
                               SCHED_PRIO_NORMAL);
    SELFTEST_ASSERT(!r.is_error, 1);
    r = sched_create_task_prio(pi_test_high_prio_waiter, NULL, SCHED_PRIO_HIGH);
    SELFTEST_ASSERT(!r.is_error, 2);

    SELFTEST_ASSERT(!selftest_poll_flag(&(pi_test_done), 20, 50), 3);
    SELFTEST_ASSERT(pi_test_holder_boosted, 4);

    return 0;
}
DEFINE_SELFTEST(mutex_priority_inheritance, test_mutex_priority_inheritance);

/* Test 4: two tasks contend on mutex, increment shared counter.
 * Result must equal exactly 2 * iterations.
 */
static struct pi_mutex contend_mtx;
static volatile i32 contend_counter;
#define CONTEND_ITERS 10

static void contend_worker(void *ctx __unused)
{
    for (i32 i = 0; i < CONTEND_ITERS; i++) {
        pi_mutex_lock(&contend_mtx);
        __atomic_fetch_add(&contend_counter, 1, __ATOMIC_RELAXED);
        pi_mutex_unlock(&contend_mtx);
    }
}

static i32 test_mutex_contention(void)
{
    pi_mutex_init(&contend_mtx);
    contend_counter = 0;

    struct result r;
    r = sched_create_task(contend_worker, NULL);
    SELFTEST_ASSERT(!r.is_error, 1);
    r = sched_create_task(contend_worker, NULL);
    SELFTEST_ASSERT(!r.is_error, 2);

    SELFTEST_ASSERT(
        !selftest_poll_count(&(contend_counter), 2 * CONTEND_ITERS, 60, 30), 3);
    SELFTEST_ASSERT(__atomic_load_n(&contend_counter, __ATOMIC_ACQUIRE) ==
                        2 * CONTEND_ITERS,
                    4);

    return 0;
}
DEFINE_SELFTEST(mutex_contention, test_mutex_contention);

/* Test 5: multi-mutex priority recomputation.
 * Task holds two mutexes (M1 and M2).  A high-priority task contends
 * on M1, boosting the holder.  Unlocking M2 must NOT drop the boost
 * inherited from M1's waiter.
 */
static struct pi_mutex multi_mtx1;
static struct pi_mutex multi_mtx2;
static volatile bool multi_holder_locked;
static volatile bool multi_holder_kept_boost;
static volatile bool multi_done;

static void multi_holder_task(void *ctx __unused)
{
    pi_mutex_lock(&multi_mtx1);
    pi_mutex_lock(&multi_mtx2);
    multi_holder_locked = true;

    /* Let the high-priority task run and contend on M1. */
    SELFTEST_KICK_AND_YIELD(80);

    /* Unlock M2 first; priority should remain boosted because
     * M1 still has a high-priority waiter.
     */
    pi_mutex_unlock(&multi_mtx2);

    struct sched_task *self = sched_current_task();
    multi_holder_kept_boost = (self->td_prio > SCHED_PRIO_NORMAL);

    pi_mutex_unlock(&multi_mtx1);
}

static void multi_waiter_task(void *ctx __unused)
{
    while (!multi_holder_locked)
        SELFTEST_KICK_AND_YIELD(10);

    /* Block on M1, triggering PI boost on the holder. */
    pi_mutex_lock(&multi_mtx1);
    pi_mutex_unlock(&multi_mtx1);

    multi_done = true;
}

static i32 test_mutex_multi_prio(void)
{
    pi_mutex_init(&multi_mtx1);
    pi_mutex_init(&multi_mtx2);
    multi_holder_locked = false;
    multi_holder_kept_boost = false;
    multi_done = false;

    struct result r;
    r = sched_create_task_prio(multi_holder_task, NULL, SCHED_PRIO_NORMAL);
    SELFTEST_ASSERT(!r.is_error, 1);
    r = sched_create_task_prio(multi_waiter_task, NULL, SCHED_PRIO_HIGH);
    SELFTEST_ASSERT(!r.is_error, 2);

    SELFTEST_ASSERT(!selftest_poll_flag(&(multi_done), 40, 50), 3);
    SELFTEST_ASSERT(multi_holder_kept_boost, 4);

    return 0;
}
DEFINE_SELFTEST(mutex_multi_prio, test_mutex_multi_prio);

/* Test 6: a task that exits while holding a mutex must release ownership so a
 * blocked waiter can acquire it.
 */
static struct pi_mutex owner_exit_mtx;
static volatile bool owner_exit_waiter_done;

static void owner_exit_holder(void *ctx __unused)
{
    pi_mutex_lock(&owner_exit_mtx);
    /* Return without unlocking; deferred cleanup must release the mutex. */
}

static void owner_exit_waiter(void *ctx __unused)
{
    pi_mutex_lock(&owner_exit_mtx);
    pi_mutex_unlock(&owner_exit_mtx);
    owner_exit_waiter_done = true;
}

static i32 test_mutex_owner_exit_release(void)
{
    pi_mutex_init(&owner_exit_mtx);
    owner_exit_waiter_done = false;

    struct result r;
    r = sched_create_task(owner_exit_holder, NULL);
    SELFTEST_ASSERT(!r.is_error, 1);
    r = sched_create_task(owner_exit_waiter, NULL);
    SELFTEST_ASSERT(!r.is_error, 2);

    SELFTEST_ASSERT(!selftest_poll_flag(&(owner_exit_waiter_done), 40, 50), 3);
    SELFTEST_ASSERT(owner_exit_mtx.owner == NULL, 4);

    return 0;
}
DEFINE_SELFTEST(mutex_owner_exit_release, test_mutex_owner_exit_release);

static struct pi_mutex timed_mtx;
static volatile bool timed_holder_ready;
static volatile bool timed_holder_released;

static void timed_holder_task(void *ctx __unused)
{
    pi_mutex_lock(&timed_mtx);
    timed_holder_ready = true;
    SELFTEST_KICK_AND_YIELD(80);
    pi_mutex_unlock(&timed_mtx);
    timed_holder_released = true;
}

static i32 test_mutex_timedlock_timeout(void)
{
    pi_mutex_init(&timed_mtx);
    timed_holder_ready = false;
    timed_holder_released = false;

    struct result r =
        sched_create_task_prio(timed_holder_task, NULL, SCHED_PRIO_NORMAL);
    SELFTEST_ASSERT(!r.is_error, 1);
    SELFTEST_ASSERT(!selftest_poll_flag(&timed_holder_ready, 20, 10), 2);
    SELFTEST_ASSERT(
        pi_mutex_lock_timed(&timed_mtx, time_ms_new(1)) == -(i32) ETIMEDOUT, 3);
    SELFTEST_ASSERT(!selftest_poll_flag(&timed_holder_released, 20, 10), 4);

    SELFTEST_ASSERT(pi_mutex_lock_timed(&timed_mtx, time_ms_new(20)) == 0, 5);
    pi_mutex_unlock(&timed_mtx);
    return 0;
}
DEFINE_SELFTEST(mutex_timedlock_timeout, test_mutex_timedlock_timeout);

static struct pi_mutex transitive_mtx1;
static struct pi_mutex transitive_mtx2;
static volatile bool transitive_c_locked;
static volatile bool transitive_b_locked;
static volatile bool transitive_c_boosted;
static volatile bool transitive_done;

static void transitive_low_owner(void *ctx __unused)
{
    pi_mutex_lock(&transitive_mtx2);
    transitive_c_locked = true;

    for (i32 i = 0; i < 40; i++) {
        if (sched_current_task()->td_prio >= SCHED_PRIO_HIGH) {
            transitive_c_boosted = true;
            break;
        }
        SELFTEST_KICK_AND_YIELD(10);
    }

    pi_mutex_unlock(&transitive_mtx2);
}

static void transitive_mid_owner(void *ctx __unused)
{
    while (!transitive_c_locked)
        SELFTEST_KICK_AND_YIELD(5);

    pi_mutex_lock(&transitive_mtx1);
    transitive_b_locked = true;
    pi_mutex_lock(&transitive_mtx2);
    pi_mutex_unlock(&transitive_mtx2);
    pi_mutex_unlock(&transitive_mtx1);
}

static void transitive_high_waiter(void *ctx __unused)
{
    while (!transitive_b_locked)
        SELFTEST_KICK_AND_YIELD(5);

    pi_mutex_lock(&transitive_mtx1);
    pi_mutex_unlock(&transitive_mtx1);
    transitive_done = true;
}

static i32 test_mutex_transitive_pi(void)
{
    pi_mutex_init(&transitive_mtx1);
    pi_mutex_init(&transitive_mtx2);
    transitive_c_locked = false;
    transitive_b_locked = false;
    transitive_c_boosted = false;
    transitive_done = false;

    struct result r;
    r = sched_create_task_prio(transitive_low_owner, NULL, SCHED_PRIO_IDLE);
    SELFTEST_ASSERT(!r.is_error, 1);
    r = sched_create_task_prio(transitive_mid_owner, NULL, SCHED_PRIO_NORMAL);
    SELFTEST_ASSERT(!r.is_error, 2);
    r = sched_create_task_prio(transitive_high_waiter, NULL, SCHED_PRIO_HIGH);
    SELFTEST_ASSERT(!r.is_error, 3);

    SELFTEST_ASSERT(!selftest_poll_flag(&transitive_done, 40, 10), 4);
    SELFTEST_ASSERT(transitive_c_boosted, 5);
    return 0;
}
DEFINE_SELFTEST(mutex_transitive_pi, test_mutex_transitive_pi);

static i32 test_mutex_refreshes_upstream_futex_donation(void)
{
    struct sched_task *owner = alloc_mock_task();
    struct sched_task *waiter = alloc_mock_task();
    if (!owner || !waiter) {
        if (owner)
            free_mock_task(owner);
        if (waiter)
            free_mock_task(waiter);
        return 1;
    }

    list_init(&owner->pi_held_mutexes);
    list_init(&owner->pi_held_futexes);
    owner->td_base_prio = SCHED_PRIO_IDLE;
    owner->td_prio = SCHED_PRIO_IDLE;

    list_init(&waiter->pi_held_mutexes);
    list_init(&waiter->pi_held_futexes);
    waiter->td_base_prio = SCHED_PRIO_NORMAL;
    waiter->td_prio = SCHED_PRIO_NORMAL;
    waiter->state = TD_STATE_BLOCKED;

    struct pi_mutex mtx;
    pi_mutex_init(&mtx);
    mtx.owner = owner;
    list_add(&owner->pi_held_mutexes, &mtx.pi_held);

    struct pi_mutex_waiter w = {
        .task = waiter,
        .granted = false,
    };
    list_init(&w.node);
    list_add_tail(&mtx.waiters, &w.node);

    waiter->td_waiting_on_task = owner;
    waiter->td_waiting_on_mutex = &mtx;
    waiter->td_waiting_on_futex = NULL;

    pi_mutex_refresh_prio(waiter);
    SELFTEST_ASSERT(waiter->td_prio == SCHED_PRIO_NORMAL, 2);
    SELFTEST_ASSERT(owner->td_prio == SCHED_PRIO_NORMAL, 3);
    SELFTEST_ASSERT(mtx.top_waiter_prio == SCHED_PRIO_NORMAL, 4);

    waiter->td_futex_pi_prio = SCHED_PRIO_HIGH;
    pi_mutex_refresh_prio(waiter);
    SELFTEST_ASSERT(waiter->td_prio == SCHED_PRIO_HIGH, 5);
    SELFTEST_ASSERT(owner->td_prio == SCHED_PRIO_HIGH, 6);
    SELFTEST_ASSERT(mtx.top_waiter_prio == SCHED_PRIO_HIGH, 7);

    waiter->td_futex_pi_prio = 0;
    pi_mutex_refresh_prio(waiter);
    SELFTEST_ASSERT(waiter->td_prio == SCHED_PRIO_NORMAL, 8);
    SELFTEST_ASSERT(owner->td_prio == SCHED_PRIO_NORMAL, 9);
    SELFTEST_ASSERT(mtx.top_waiter_prio == SCHED_PRIO_NORMAL, 10);

    list_del_init(&w.node);
    list_del_init(&mtx.pi_held);
    free_mock_task(waiter);
    free_mock_task(owner);
    return 0;
}
DEFINE_SELFTEST(mutex_refreshes_upstream_futex_donation,
                test_mutex_refreshes_upstream_futex_donation);
