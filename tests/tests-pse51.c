/* SPDX-License-Identifier: MIT */
/* PSE51 conformance smoke tests.
 *
 * Exercises the PSE51-facing surface: clocks, sleep, sync primitives,
 * scheduling control, barriers, rwlocks, message queues.
 * Each test validates a minimal operation of its subsystem.
 */

#include <kernel/ipc/mqueue.h>
#include <kernel/sync/barrier.h>
#include <kernel/sync/condvar.h>
#include <kernel/sync/mutex.h>
#include <kernel/sync/rwlock.h>
#include <kernel/sync/semaphore.h>
#include <kernel/sync/sync_handle.h>
#include <mazu/ipi.h>
#include <mazu/posix_time.h>
#include <mazu/sched.h>
#include <mazu/time.h>
#include "tests-common.h"

/* Smoke 1: clock monotonicity and resolution. */
static i32 test_pse51_clocks(void)
{
    u64 freq = time_get_timebase_freq();
    SELFTEST_ASSERT(freq > 0, 1);

    u64 t1 = time_rdtime();
    for (volatile i32 v = 0; v < 10; v++)
        ;
    u64 t2 = time_rdtime();
    SELFTEST_ASSERT(t2 > t1, 2);

    /* Resolution should be sub-millisecond. */
    i64 res_ns = (i64) (NSEC_PER_SEC / freq);
    SELFTEST_ASSERT(res_ns > 0 && res_ns < NSEC_PER_MSEC, 3);

    return 0;
}
DEFINE_SELFTEST(pse51_clocks, test_pse51_clocks);

/* Smoke 2: nanosleep. */
static i32 test_pse51_sleep(void)
{
    u64 before = time_rdtime();
    sleep_ms(time_ms_new(20));
    u64 after = time_rdtime();
    u64 elapsed_us = time_ticks_to_us(after - before);
    SELFTEST_ASSERT(elapsed_us >= 15000, 1);
    return 0;
}
DEFINE_SELFTEST(pse51_sleep, test_pse51_sleep);

/* Smoke 3: mutex lock/unlock. */
static i32 test_pse51_mutex(void)
{
    i32 h = sync_mutex_alloc(NULL);
    SELFTEST_ASSERT(h >= 0, 1);

    struct pi_mutex *m = sync_mutex_get(h);
    SELFTEST_ASSERT(m != NULL, 2);

    pi_mutex_lock(m);
    pi_mutex_unlock(m);

    SELFTEST_ASSERT(pi_mutex_trylock(m) == 0, 3);
    pi_mutex_unlock(m);

    sync_mutex_free(h, NULL);
    return 0;
}
DEFINE_SELFTEST(pse51_mutex, test_pse51_mutex);

/* Smoke 4: semaphore with timed wait. */
static i32 test_pse51_sem(void)
{
    i32 h = sync_sem_alloc(NULL, 1);
    SELFTEST_ASSERT(h >= 0, 1);

    struct semaphore *s = sync_sem_get(h);
    SELFTEST_ASSERT(s != NULL, 2);

    sem_wait(s);
    sem_post(s);

    /* Timed wait should succeed immediately since count is now 1. */
    i32 rc = sem_timedwait(s, time_ms_new(100));
    SELFTEST_ASSERT(rc == 0, 3);

    /* Timed wait should timeout since count is now 0. */
    rc = sem_timedwait(s, time_ms_new(20));
    SELFTEST_ASSERT(rc == -(i32) ETIMEDOUT, 4);

    sem_post(s);
    sync_sem_free(h, NULL);
    return 0;
}
DEFINE_SELFTEST(pse51_sem, test_pse51_sem);

/* Smoke 5: scheduling priority query. */
static i32 test_pse51_sched(void)
{
    SELFTEST_ASSERT(SCHED_PRIO_IDLE == 0, 1);
    SELFTEST_ASSERT(CONFIG_SCHED_NPRIO > 1, 2);

    struct sched_task *td = sched_current_task();
    SELFTEST_ASSERT(td != NULL, 3);
    SELFTEST_ASSERT(td->td_base_prio >= SCHED_PRIO_IDLE, 4);

    return 0;
}
DEFINE_SELFTEST(pse51_sched, test_pse51_sched);

/* Smoke 6: message queue send/receive. */
static i32 test_pse51_mqueue(void)
{
    i32 h = mqueue_open(NULL, 4, 32);
    SELFTEST_ASSERT(h >= 0, 1);

    u8 msg[] = {1, 2, 3};
    SELFTEST_ASSERT(mqueue_send(h, msg, 3, 10) == 0, 2);

    u8 buf[32];
    u32 prio;
    i32 len = mqueue_receive(h, buf, sizeof(buf), &prio);
    SELFTEST_ASSERT(len == 3, 3);
    SELFTEST_ASSERT(prio == 10, 4);
    SELFTEST_ASSERT(buf[0] == 1 && buf[1] == 2 && buf[2] == 3, 5);

    mqueue_close(h);
    return 0;
}
DEFINE_SELFTEST(pse51_mqueue, test_pse51_mqueue);

/* Smoke 7: barrier with 1 thread (trivial case). */
static i32 test_pse51_barrier_trivial(void)
{
    struct barrier b;
    barrier_init(&b, 1);

    i32 ret = barrier_wait(&b);
    SELFTEST_ASSERT(ret == PTHREAD_BARRIER_SERIAL_THREAD, 1);

    SELFTEST_ASSERT(barrier_destroy(&b) == 0, 2);
    return 0;
}
DEFINE_SELFTEST(pse51_barrier_trivial, test_pse51_barrier_trivial);

/* Smoke 8: rwlock basic read/write. */
static i32 test_pse51_rwlock(void)
{
    struct rwlock rw;
    rwlock_init(&rw);

    rwlock_rdlock(&rw);
    rwlock_unlock(&rw);

    rwlock_wrlock(&rw);
    rwlock_unlock(&rw);

    SELFTEST_ASSERT(rwlock_tryrdlock(&rw) == 0, 1);
    rwlock_unlock(&rw);

    SELFTEST_ASSERT(rwlock_trywrlock(&rw) == 0, 2);
    rwlock_unlock(&rw);

    SELFTEST_ASSERT(rwlock_destroy(&rw) == 0, 3);
    return 0;
}
DEFINE_SELFTEST(pse51_rwlock, test_pse51_rwlock);
