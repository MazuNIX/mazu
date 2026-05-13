/* SPDX-License-Identifier: MIT */
/* PSE51 conformance suite.
 *
 * Inspired by externals/posix-conformance: group checks by API
 * category, cover positive plus targeted negative/boundary cases,
 * and exercise the user-visible syscall semantics where practical.
 *
 * Lower-level primitive tests still live in the subsystem-specific
 * selftests. This file is the consolidated "does the PSE51-facing
 * surface still match the matrix?" suite.
 */

#include <kernel/proc/pipe.h>
#include <mazu/cap.h>
#include <mazu/ipi.h>
#include <mazu/list.h>
#include <mazu/posix_time.h>
#include <mazu/pthread.h>
#include <mazu/selftest.h>
#include <mazu/syscall.h>
#include <mazu/sysconf.h>
#include <mazu/time.h>
#include <mazu/uaccess.h>
#include "tests-common.h"
#include "tests-proc-helpers.h"

static bool pse51_map_user_page(struct proc *p, vaddr_t va)
{
    return !proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error;
}

static i32 test_pse51_sysconf_profile(void)
{
    SELFTEST_ASSERT(sys_sysconf_query(_SC_TIMERS) == _POSIX_TIMERS, 1);
    SELFTEST_ASSERT(
        sys_sysconf_query(_SC_MONOTONIC_CLOCK) == _POSIX_MONOTONIC_CLOCK, 2);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_PRIORITY_SCHEDULING) ==
                        _POSIX_PRIORITY_SCHEDULING,
                    3);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_SEMAPHORES) == _POSIX_SEMAPHORES, 4);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_BARRIERS) == _POSIX_BARRIERS, 5);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_READER_WRITER_LOCKS) ==
                        _POSIX_READER_WRITER_LOCKS,
                    6);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_THREAD_PRIORITY_INHERIT) ==
                        _POSIX_THREAD_PRIO_INHERIT,
                    7);
    SELFTEST_ASSERT(
        sys_sysconf_query(_SC_MESSAGE_PASSING) == _POSIX_MESSAGE_PASSING, 8);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_THREADS) == _POSIX_THREADS, 9);
    SELFTEST_ASSERT(
        sys_sysconf_query(_SC_THREAD_CPUTIME) == _POSIX_THREAD_CPUTIME, 10);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_CPUTIME) == _POSIX_CPUTIME, 11);
    SELFTEST_ASSERT(
        sys_sysconf_query(_SC_REALTIME_SIGNALS) == _POSIX_REALTIME_SIGNALS, 12);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_SPIN_LOCKS) == -1, 13);
    SELFTEST_ASSERT(
        sys_sysconf_query(_SC_CLOCK_SELECTION) == _POSIX_CLOCK_SELECTION, 14);
    SELFTEST_ASSERT(sys_sysconf_query(_SC_TIMEOUTS) == _POSIX_TIMEOUTS, 15);
    SELFTEST_ASSERT(
        sys_sysconf_query(_SC_SYNCHRONIZED_IO) == _POSIX_SYNCHRONIZED_IO, 16);
    return 0;
}
DEFINE_SELFTEST(pse51_sysconf_profile, test_pse51_sysconf_profile);

static i32 test_pse51_time_profile(void)
{
    struct proc *p;
    struct sched_task *td;
    struct trap_frame tf = {0};
    struct timespec ts;
    const vaddr_t va = USER_DATA_BASE + (180UL * PAGE_SIZE);

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);
    SELFTEST_ASSERT(pse51_map_user_page(p, va), 2);

    tf.a7 = SYS_CLOCK_GETTIME;
    tf.a0 = CLOCK_MONOTONIC;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 3);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 4);
    SELFTEST_ASSERT(ts.tv_nsec >= 0 && ts.tv_nsec < NSEC_PER_SEC, 5);

    tf.a0 = CLOCK_REALTIME;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 6);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 7);
    SELFTEST_ASSERT(ts.tv_nsec >= 0 && ts.tv_nsec < NSEC_PER_SEC, 8);
    struct timespec orig_rt = ts;

    td->cpu_time_us = 1234567ULL;
    tf.a0 = CLOCK_THREAD_CPUTIME_ID;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 9);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 10);
    SELFTEST_ASSERT(ts.tv_sec == 1 && ts.tv_nsec == 234567000, 11);

    tf.a0 = CLOCK_PROCESS_CPUTIME_ID;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 12);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 13);
    SELFTEST_ASSERT(ts.tv_sec == 1 && ts.tv_nsec == 234567000, 14);

    tf.a7 = SYS_CLOCK_GETRES;
    tf.a0 = CLOCK_MONOTONIC;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 15);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 16);
    SELFTEST_ASSERT(ts.tv_sec >= 0 && ts.tv_nsec > 0, 17);

    tf.a7 = SYS_NANOSLEEP;
    tf.a0 = (u64) va;
    tf.a1 = 0;
    ts.tv_sec = 0;
    ts.tv_nsec = -1;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 18);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 19);

    ts.tv_sec = -1;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 20);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 21);

    ts.tv_sec = 0;
    ts.tv_nsec = (i64) NSEC_PER_SEC;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 22);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 23);

    tf.a7 = SYS_CLOCK_GETTIME;
    tf.a0 = CLOCK_MONOTONIC;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 24);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 25);
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 26);
    struct timespec rem = {.tv_sec = 7, .tv_nsec = 11};
    SELFTEST_ASSERT(copy_to_user(va + 32, &rem, sizeof(rem)) == 0, 27);
    tf.a7 = SYS_CLOCK_NANOSLEEP;
    tf.a0 = CLOCK_MONOTONIC;
    tf.a1 = TIMER_ABSTIME;
    tf.a2 = (u64) va;
    tf.a3 = (u64) (va + 32);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 28);
    SELFTEST_ASSERT(copy_from_user(&rem, va + 32, sizeof(rem)) == 0, 29);
    SELFTEST_ASSERT(rem.tv_sec == 7 && rem.tv_nsec == 11, 30);

    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 31);
    tf.a0 = CLOCK_PROCESS_CPUTIME_ID;
    tf.a1 = 0;
    tf.a2 = (u64) va;
    tf.a3 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 32);

    ts.tv_sec = orig_rt.tv_sec + 2;
    ts.tv_nsec = orig_rt.tv_nsec;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 33);
    tf.a7 = SYS_CLOCK_SETTIME;
    tf.a0 = CLOCK_REALTIME;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 34);

    tf.a7 = SYS_CLOCK_GETTIME;
    tf.a0 = CLOCK_REALTIME;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 35);
    SELFTEST_ASSERT(copy_from_user(&ts, va, sizeof(ts)) == 0, 36);
    SELFTEST_ASSERT(ts.tv_sec >= orig_rt.tv_sec + 2, 37);

    tf.a7 = SYS_CLOCK_SETTIME;
    tf.a0 = CLOCK_MONOTONIC;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 38);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_time_profile, test_pse51_time_profile);

static i32 test_pse51_memory_syncio_profile(void)
{
    struct proc *p;
    struct sched_task *td;
    struct trap_frame tf = {0};
    const vaddr_t va = USER_DATA_BASE + (181UL * PAGE_SIZE);
    struct pipe *pipe;

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);
    SELFTEST_ASSERT(pse51_map_user_page(p, va), 2);

    tf.a7 = SYS_MLOCK;
    tf.a0 = (u64) va;
    tf.a1 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 3);

    tf.a0 = U64_MAX - 16;
    tf.a1 = 64;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 4);

    tf.a0 = 0;
    tf.a1 = 16;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ENOMEM, 5);

    tf.a0 = (u64) va;
    tf.a1 = 16;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 6);

    tf.a7 = SYS_MUNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 7);

    tf.a7 = SYS_FSYNC;
    tf.a0 = (u64) -1;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EBADF, 8);

    tf.a7 = SYS_FDATASYNC;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EBADF, 9);

    tf.a7 = SYS_FSYNC;
    tf.a0 = PROC_FD_STDOUT;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 10);

    tf.a7 = SYS_FDATASYNC;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 11);

    pipe = pipe_alloc();
    SELFTEST_ASSERT(pipe != NULL, 12);
    SELFTEST_ASSERT(
        cap_open_pipe(p, pipe, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT,
                      PROC_FD_STDIN, true) == PROC_FD_STDIN,
        13);

    tf.a7 = SYS_FSYNC;
    tf.a0 = PROC_FD_STDIN;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 14);

    tf.a7 = SYS_FDATASYNC;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 15);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_memory_syncio_profile, test_pse51_memory_syncio_profile);

static i32 test_pse51_sync_profile(void)
{
    struct proc *p;
    struct sched_task *td;
    struct trap_frame tf = {0};
    struct timespec ts = {0};
    i64 mutex_h;
    i64 cond_h;
    i64 sem_h;
    i64 barrier_h;
    i64 rwlock_h;
    const vaddr_t va = USER_DATA_BASE + (182UL * PAGE_SIZE);

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);
    SELFTEST_ASSERT(pse51_map_user_page(p, va), 2);

    tf.a7 = SYS_MUTEX_INIT;
    mutex_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(mutex_h >= 0, 3);

    tf.a7 = SYS_MUTEX_LOCK;
    tf.a0 = (u64) mutex_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 4);

    tf.a7 = SYS_MUTEX_UNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 5);

    tf.a7 = SYS_MUTEX_TRYLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 6);
    tf.a7 = SYS_MUTEX_UNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 7);

    tf.a7 = SYS_MUTEX_LOCK;
    tf.a0 = (u64) mutex_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 8);
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 9);
    tf.a7 = SYS_MUTEX_TIMEDLOCK;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 10);
    tf.a7 = SYS_MUTEX_UNLOCK;
    tf.a1 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 11);

    tf.a7 = SYS_COND_INIT;
    cond_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(cond_h >= 0, 12);

    tf.a7 = SYS_COND_SIGNAL;
    tf.a0 = (u64) cond_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 13);

    tf.a7 = SYS_COND_BROADCAST;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 14);

    tf.a7 = SYS_SEM_INIT;
    tf.a0 = 1;
    sem_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(sem_h >= 0, 15);

    tf.a7 = SYS_SEM_WAIT;
    tf.a0 = (u64) sem_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 16);

    tf.a7 = SYS_SEM_POST;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 17);

    tf.a7 = SYS_SEM_TRYWAIT;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 18);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 19);
    tf.a7 = SYS_SEM_TIMEDWAIT;
    tf.a0 = (u64) sem_h;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 20);

    tf.a7 = SYS_BARRIER_INIT;
    tf.a0 = 1;
    barrier_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(barrier_h >= 0, 21);

    tf.a7 = SYS_BARRIER_WAIT;
    tf.a0 = (u64) barrier_h;
    SELFTEST_ASSERT(
        syscall_dispatch(&tf, td) == (i64) PTHREAD_BARRIER_SERIAL_THREAD, 22);

    tf.a7 = SYS_BARRIER_DESTROY;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 23);

    tf.a7 = SYS_RWLOCK_INIT;
    rwlock_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(rwlock_h >= 0, 24);

    tf.a7 = SYS_RWLOCK_RDLOCK;
    tf.a0 = (u64) rwlock_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 25);

    tf.a7 = SYS_RWLOCK_UNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 26);

    tf.a7 = SYS_RWLOCK_TRYWRLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 27);

    tf.a7 = SYS_RWLOCK_UNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 28);

    tf.a7 = SYS_RWLOCK_WRLOCK;
    tf.a0 = (u64) rwlock_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 29);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 30);
    tf.a7 = SYS_RWLOCK_TIMEDRDLOCK;
    tf.a0 = (u64) rwlock_h;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 31);

    tf.a7 = SYS_RWLOCK_UNLOCK;
    tf.a0 = (u64) rwlock_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 32);

    tf.a7 = SYS_RWLOCK_DESTROY;
    tf.a0 = (u64) rwlock_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 33);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_sync_profile, test_pse51_sync_profile);

static i32 test_pse51_sched_thread_profile(void)
{
    struct proc *p;
    struct sched_task *td;
    struct sched_task *target;
    struct trap_frame tf = {0};
    i32 old_state = 0;

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);
    td->td_base_prio = (u8) (CONFIG_SCHED_NPRIO - 1);
    list_init(&td->pi_held_mutexes);

    tf.a7 = SYS_THREAD_SELF;
    SELFTEST_ASSERT(
        syscall_dispatch(&tf, td) == syscall_test_thread_token(p, td), 2);

    tf.a7 = SYS_THREAD_GETSCHEDPARAM;
    tf.a0 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == (i64) td->td_base_prio, 3);

    tf.a7 = SYS_THREAD_SETSCHEDPARAM;
    tf.a0 = 0;
    tf.a1 = SCHED_PRIO_IDLE;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 4);
    SELFTEST_ASSERT(td->td_base_prio == SCHED_PRIO_IDLE, 5);

    tf.a7 = SYS_SCHED_GETSCHEDULER;
    tf.a0 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == (i64) SCHED_FIFO, 6);

    tf.a7 = SYS_SCHED_SETSCHEDULER;
    tf.a0 = 0;
    tf.a1 = SCHED_OTHER;
    tf.a2 = SCHED_PRIO_IDLE;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == (i64) SCHED_FIFO, 7);

    target = alloc_mock_task();
    SELFTEST_ASSERT(target != NULL, 8);
    target->proc = p;
    target->td_join_state = TD_JOIN_JOINABLE;
    init_waitqueue_head(&target->td_join_wq);
    SELFTEST_ASSERT(attach_mock_thread(p, target), 9);

    tf.a7 = SYS_THREAD_DETACH;
    tf.a0 = (u64) syscall_test_thread_token(p, target);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 10);
    SELFTEST_ASSERT(target->td_join_state == TD_JOIN_DETACHED, 11);

    tf.a7 = SYS_THREAD_JOIN;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 12);

    tf.a0 = (u64) syscall_test_thread_token(p, td);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EDEADLK, 13);

    tf.a7 = SYS_THREAD_SETCANCELSTATE;
    tf.a0 = PTHREAD_CANCEL_DISABLE;
    tf.a1 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 14);
    old_state =
        td->td_cancel_disabled ? PTHREAD_CANCEL_DISABLE : PTHREAD_CANCEL_ENABLE;
    SELFTEST_ASSERT(old_state == PTHREAD_CANCEL_DISABLE, 15);

    tf.a0 = PTHREAD_CANCEL_ENABLE;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 16);
    SELFTEST_ASSERT(td->td_cancel_disabled == false, 17);

    tf.a7 = SYS_THREAD_CANCEL;
    tf.a0 = (u64) syscall_test_thread_token(p, td);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 18);
    SELFTEST_ASSERT(td->td_cancel_pending == true, 19);

    td->td_cancel_disabled = true;
    tf.a7 = SYS_THREAD_TESTCANCEL;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 20);

    {
        u64 flags = proc_table_lock_irqsave();
        proc_detach_task(p, target);
        proc_table_unlock_irqrestore(flags);
    }
    free_mock_task(target);
    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_sched_thread_profile, test_pse51_sched_thread_profile);

static i32 test_pse51_pthread_attr_profile(void)
{
    pthread_attr_t attr;
    i32 state = 0;
    i32 inheritsched = 0;
    i32 policy = 0;
    sz size = 0;
    void *addr = NULL;
    struct sched_param param;

    /* NULL guards on every entry point. */
    SELFTEST_ASSERT(pthread_attr_init(NULL) == EINVAL, 1);
    SELFTEST_ASSERT(pthread_attr_destroy(NULL) == EINVAL, 2);
    SELFTEST_ASSERT(pthread_attr_setdetachstate(NULL, 0) == EINVAL, 3);
    SELFTEST_ASSERT(pthread_attr_getdetachstate(NULL, &state) == EINVAL, 4);
    SELFTEST_ASSERT(pthread_attr_setinheritsched(NULL, 0) == EINVAL, 5);
    SELFTEST_ASSERT(pthread_attr_getinheritsched(NULL, &inheritsched) == EINVAL,
                    6);
    SELFTEST_ASSERT(pthread_attr_setschedpolicy(NULL, SCHED_FIFO) == EINVAL, 7);
    SELFTEST_ASSERT(pthread_attr_getschedpolicy(NULL, &policy) == EINVAL, 8);
    SELFTEST_ASSERT(pthread_attr_setschedparam(NULL, &param) == EINVAL, 9);
    SELFTEST_ASSERT(pthread_attr_getschedparam(NULL, &param) == EINVAL, 10);
    SELFTEST_ASSERT(
        pthread_attr_setstacksize(NULL, PTHREAD_STACK_MIN) == EINVAL, 11);
    SELFTEST_ASSERT(pthread_attr_getstacksize(NULL, &size) == EINVAL, 12);
    SELFTEST_ASSERT(
        pthread_attr_setstack(NULL, NULL, PTHREAD_STACK_MIN) == EINVAL, 13);
    SELFTEST_ASSERT(pthread_attr_getstack(NULL, &addr, &size) == EINVAL, 14);

    SELFTEST_ASSERT(pthread_attr_init(&attr) == 0, 20);

    /* Defaults match POSIX: joinable, inherit-sched, FIFO, normal prio. */
    SELFTEST_ASSERT(pthread_attr_getdetachstate(&attr, &state) == 0, 21);
    SELFTEST_ASSERT(state == PTHREAD_CREATE_JOINABLE, 22);
    SELFTEST_ASSERT(pthread_attr_getinheritsched(&attr, &inheritsched) == 0,
                    23);
    SELFTEST_ASSERT(inheritsched == PTHREAD_INHERIT_SCHED, 24);
    SELFTEST_ASSERT(pthread_attr_getschedpolicy(&attr, &policy) == 0, 25);
    SELFTEST_ASSERT(policy == SCHED_FIFO, 26);
    SELFTEST_ASSERT(pthread_attr_getschedparam(&attr, &param) == 0, 27);
    SELFTEST_ASSERT(param.sched_priority == SCHED_PRIO_NORMAL, 28);
    SELFTEST_ASSERT(pthread_attr_getstacksize(&attr, &size) == 0, 29);
    SELFTEST_ASSERT(size == USER_STACK_SIZE, 30);

    /* detachstate: valid round-trip, invalid value rejected. */
    SELFTEST_ASSERT(
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0, 31);
    SELFTEST_ASSERT(pthread_attr_getdetachstate(&attr, &state) == 0, 32);
    SELFTEST_ASSERT(state == PTHREAD_CREATE_DETACHED, 33);
    SELFTEST_ASSERT(pthread_attr_setdetachstate(&attr, 99) == EINVAL, 34);
    SELFTEST_ASSERT(pthread_attr_getdetachstate(&attr, &state) == 0, 35);
    SELFTEST_ASSERT(state == PTHREAD_CREATE_DETACHED, 36);

    /* inheritsched: valid round-trip, invalid value rejected. */
    SELFTEST_ASSERT(
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0, 40);
    SELFTEST_ASSERT(pthread_attr_getinheritsched(&attr, &inheritsched) == 0,
                    41);
    SELFTEST_ASSERT(inheritsched == PTHREAD_EXPLICIT_SCHED, 42);
    SELFTEST_ASSERT(pthread_attr_setinheritsched(&attr, 99) == EINVAL, 43);

    /* schedpolicy: all three POSIX policies round-trip; bad value rejected. */
    SELFTEST_ASSERT(pthread_attr_setschedpolicy(&attr, SCHED_OTHER) == 0, 50);
    SELFTEST_ASSERT(pthread_attr_getschedpolicy(&attr, &policy) == 0, 51);
    SELFTEST_ASSERT(policy == SCHED_OTHER, 52);
    SELFTEST_ASSERT(pthread_attr_setschedpolicy(&attr, SCHED_RR) == 0, 53);
    SELFTEST_ASSERT(pthread_attr_getschedpolicy(&attr, &policy) == 0, 54);
    SELFTEST_ASSERT(policy == SCHED_RR, 55);
    SELFTEST_ASSERT(pthread_attr_setschedpolicy(&attr, 0xFF) == EINVAL, 56);

    /* schedparam: bounds checked against the kernel range. */
    param.sched_priority = SCHED_PRIO_IDLE;
    SELFTEST_ASSERT(pthread_attr_setschedparam(&attr, &param) == 0, 60);
    SELFTEST_ASSERT(pthread_attr_getschedparam(&attr, &param) == 0, 61);
    SELFTEST_ASSERT(param.sched_priority == SCHED_PRIO_IDLE, 62);
    param.sched_priority = CONFIG_SCHED_NPRIO - 1;
    SELFTEST_ASSERT(pthread_attr_setschedparam(&attr, &param) == 0, 63);
    param.sched_priority = CONFIG_SCHED_NPRIO;
    SELFTEST_ASSERT(pthread_attr_setschedparam(&attr, &param) == EINVAL, 64);
    param.sched_priority = -1;
    SELFTEST_ASSERT(pthread_attr_setschedparam(&attr, &param) == EINVAL, 65);

    /* stacksize: below-min rejected; only the kernel's fixed per-thread
     * size is accepted.
     */
    SELFTEST_ASSERT(
        pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN - 1) == EINVAL, 70);
    SELFTEST_ASSERT(
        pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN) == ENOTSUP, 71);
    SELFTEST_ASSERT(pthread_attr_getstacksize(&attr, &size) == 0, 72);
    SELFTEST_ASSERT(size == USER_STACK_SIZE, 73);
    SELFTEST_ASSERT(pthread_attr_setstacksize(&attr, USER_STACK_SIZE) == 0, 74);
    SELFTEST_ASSERT(pthread_attr_getstacksize(&attr, &size) == 0, 75);
    SELFTEST_ASSERT(size == USER_STACK_SIZE, 76);

    /* setstack always returns ENOTSUP. POSIX semantics need a real
     * caller-supplied stack region; Mazu's shared-VA model places every
     * thread's stack at a fixed kernel-chosen VA, so the call cannot
     * be honored. getstack still round-trips whatever pthread_attr_init
     * stored.
     */
    SELFTEST_ASSERT(
        pthread_attr_setstack(&attr, NULL, PTHREAD_STACK_MIN) == ENOTSUP, 80);
    SELFTEST_ASSERT(pthread_attr_setstack(&attr, (void *) 0x10000,
                                          PTHREAD_STACK_MIN) == ENOTSUP,
                    81);
    SELFTEST_ASSERT(pthread_attr_getstack(&attr, &addr, &size) == 0, 82);
    SELFTEST_ASSERT(addr == NULL, 83);

    /* Resolve helpers: inherit-sched uses the historical two-argument
     * SYS_THREAD_CREATE ABI. EXPLICIT_SCHED selects the dedicated
     * SYS_THREAD_CREATE_EXPLICIT entry point and encodes (prio + 1) in
     * a2. If a caller has bypassed the setters and parked an out-of-range
     * priority, the helper passes it through and the kernel returns
     * EINVAL, instead of silently demoting the request to inherit.
     */
    SELFTEST_ASSERT(
        pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED) == 0, 90);
    param.sched_priority = SCHED_PRIO_HIGH;
    SELFTEST_ASSERT(pthread_attr_setschedparam(&attr, &param) == 0, 91);
    SELFTEST_ASSERT(
        pthread_attr_resolve_create_syscall(&attr) == SYS_THREAD_CREATE, 92);
    SELFTEST_ASSERT(pthread_attr_resolve_prio_arg(&attr) == 0, 93);
    SELFTEST_ASSERT(
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0, 94);
    SELFTEST_ASSERT(pthread_attr_resolve_create_syscall(&attr) ==
                        SYS_THREAD_CREATE_EXPLICIT,
                    95);
    SELFTEST_ASSERT(
        pthread_attr_resolve_prio_arg(&attr) == (u64) (SCHED_PRIO_HIGH + 1),
        96);
    SELFTEST_ASSERT(
        pthread_attr_resolve_create_syscall(NULL) == SYS_THREAD_CREATE, 97);
    SELFTEST_ASSERT(pthread_attr_resolve_prio_arg(NULL) == 0, 98);
    /* Direct-write out-of-range priority encodes to a sentinel above
     * CONFIG_SCHED_NPRIO, which the kernel's a2 bound check rejects.
     * The negative case is the load-bearing one: a naive (u64) cast
     * of i32 -1 plus 1 wraps to 0 and would mimic the inherit
     * encoding, so the bound check has to run before the cast.
     */
    attr.sched_priority = CONFIG_SCHED_NPRIO + 5;
    SELFTEST_ASSERT(
        pthread_attr_resolve_prio_arg(&attr) > (u64) CONFIG_SCHED_NPRIO, 99);
    attr.sched_priority = -1;
    SELFTEST_ASSERT(
        pthread_attr_resolve_prio_arg(&attr) > (u64) CONFIG_SCHED_NPRIO, 100);

    SELFTEST_ASSERT(pthread_attr_destroy(&attr) == 0, 101);
    return 0;
}
DEFINE_SELFTEST(pse51_pthread_attr_profile, test_pse51_pthread_attr_profile);

static i32 test_pse51_pthread_primitive_attr_profile(void)
{
    pthread_mutexattr_t mtx;
    pthread_condattr_t cond;
    pthread_rwlockattr_t rw;
    pthread_barrierattr_t bar;
    i32 v = 0;

    SELFTEST_ASSERT(pthread_mutexattr_init(NULL) == EINVAL, 1);
    SELFTEST_ASSERT(pthread_mutexattr_destroy(NULL) == EINVAL, 2);
    SELFTEST_ASSERT(
        pthread_mutexattr_settype(NULL, PTHREAD_MUTEX_NORMAL) == EINVAL, 3);
    SELFTEST_ASSERT(pthread_mutexattr_gettype(NULL, &v) == EINVAL, 4);
    SELFTEST_ASSERT(
        pthread_mutexattr_setprotocol(NULL, PTHREAD_PRIO_INHERIT) == EINVAL, 5);
    SELFTEST_ASSERT(pthread_mutexattr_getprotocol(NULL, &v) == EINVAL, 6);
    SELFTEST_ASSERT(
        pthread_mutexattr_setpshared(NULL, PTHREAD_PROCESS_PRIVATE) == EINVAL,
        7);
    SELFTEST_ASSERT(pthread_mutexattr_getpshared(NULL, &v) == EINVAL, 8);

    SELFTEST_ASSERT(pthread_mutexattr_init(&mtx) == 0, 9);
    SELFTEST_ASSERT(pthread_mutexattr_gettype(&mtx, &v) == 0, 10);
    SELFTEST_ASSERT(v == PTHREAD_MUTEX_NORMAL, 11);
    SELFTEST_ASSERT(
        pthread_mutexattr_settype(&mtx, PTHREAD_MUTEX_RECURSIVE) == 0, 12);
    SELFTEST_ASSERT(pthread_mutexattr_gettype(&mtx, &v) == 0, 13);
    SELFTEST_ASSERT(v == PTHREAD_MUTEX_RECURSIVE, 14);
    SELFTEST_ASSERT(pthread_mutexattr_settype(&mtx, 99) == EINVAL, 15);
    SELFTEST_ASSERT(
        pthread_mutexattr_setprotocol(&mtx, PTHREAD_PRIO_INHERIT) == 0, 16);
    SELFTEST_ASSERT(pthread_mutexattr_getprotocol(&mtx, &v) == 0, 17);
    SELFTEST_ASSERT(v == PTHREAD_PRIO_INHERIT, 18);
    SELFTEST_ASSERT(
        pthread_mutexattr_setprotocol(&mtx, PTHREAD_PRIO_PROTECT) == ENOTSUP,
        19);
    SELFTEST_ASSERT(
        pthread_mutexattr_setprotocol(&mtx, PTHREAD_PRIO_NONE) == ENOTSUP, 20);
    SELFTEST_ASSERT(
        pthread_mutexattr_setpshared(&mtx, PTHREAD_PROCESS_SHARED) == 0, 21);
    SELFTEST_ASSERT(pthread_mutexattr_getpshared(&mtx, &v) == 0, 22);
    SELFTEST_ASSERT(v == PTHREAD_PROCESS_SHARED, 23);
    SELFTEST_ASSERT(pthread_mutexattr_destroy(&mtx) == 0, 24);

    SELFTEST_ASSERT(pthread_condattr_init(NULL) == EINVAL, 25);
    SELFTEST_ASSERT(pthread_condattr_destroy(NULL) == EINVAL, 26);
    SELFTEST_ASSERT(
        pthread_condattr_setpshared(NULL, PTHREAD_PROCESS_PRIVATE) == EINVAL,
        27);
    SELFTEST_ASSERT(pthread_condattr_getpshared(NULL, &v) == EINVAL, 28);
    SELFTEST_ASSERT(pthread_condattr_setclock(NULL, CLOCK_REALTIME) == EINVAL,
                    29);
    SELFTEST_ASSERT(pthread_condattr_getclock(NULL, &v) == EINVAL, 30);
    SELFTEST_ASSERT(pthread_condattr_init(&cond) == 0, 31);
    SELFTEST_ASSERT(pthread_condattr_getclock(&cond, &v) == 0, 32);
    SELFTEST_ASSERT(v == CLOCK_REALTIME, 33);
    SELFTEST_ASSERT(pthread_condattr_setclock(&cond, CLOCK_MONOTONIC) == 0, 34);
    SELFTEST_ASSERT(pthread_condattr_getclock(&cond, &v) == 0, 35);
    SELFTEST_ASSERT(v == CLOCK_MONOTONIC, 36);
    SELFTEST_ASSERT(
        pthread_condattr_setpshared(&cond, PTHREAD_PROCESS_SHARED) == 0, 37);
    SELFTEST_ASSERT(pthread_condattr_getpshared(&cond, &v) == 0, 38);
    SELFTEST_ASSERT(v == PTHREAD_PROCESS_SHARED, 39);
    SELFTEST_ASSERT(pthread_condattr_destroy(&cond) == 0, 40);

    SELFTEST_ASSERT(pthread_rwlockattr_init(NULL) == EINVAL, 41);
    SELFTEST_ASSERT(pthread_rwlockattr_destroy(NULL) == EINVAL, 42);
    SELFTEST_ASSERT(
        pthread_rwlockattr_setpshared(NULL, PTHREAD_PROCESS_PRIVATE) == EINVAL,
        43);
    SELFTEST_ASSERT(pthread_rwlockattr_getpshared(NULL, &v) == EINVAL, 44);
    SELFTEST_ASSERT(pthread_rwlockattr_init(&rw) == 0, 45);
    SELFTEST_ASSERT(
        pthread_rwlockattr_setpshared(&rw, PTHREAD_PROCESS_SHARED) == 0, 46);
    SELFTEST_ASSERT(pthread_rwlockattr_getpshared(&rw, &v) == 0, 47);
    SELFTEST_ASSERT(v == PTHREAD_PROCESS_SHARED, 48);
    SELFTEST_ASSERT(pthread_rwlockattr_destroy(&rw) == 0, 49);

    SELFTEST_ASSERT(pthread_barrierattr_init(NULL) == EINVAL, 50);
    SELFTEST_ASSERT(pthread_barrierattr_destroy(NULL) == EINVAL, 51);
    SELFTEST_ASSERT(
        pthread_barrierattr_setpshared(NULL, PTHREAD_PROCESS_PRIVATE) == EINVAL,
        52);
    SELFTEST_ASSERT(pthread_barrierattr_getpshared(NULL, &v) == EINVAL, 53);
    SELFTEST_ASSERT(pthread_barrierattr_init(&bar) == 0, 54);
    SELFTEST_ASSERT(
        pthread_barrierattr_setpshared(&bar, PTHREAD_PROCESS_SHARED) == 0, 55);
    SELFTEST_ASSERT(pthread_barrierattr_getpshared(&bar, &v) == 0, 56);
    SELFTEST_ASSERT(v == PTHREAD_PROCESS_SHARED, 57);
    SELFTEST_ASSERT(pthread_barrierattr_destroy(&bar) == 0, 58);
    return 0;
}
DEFINE_SELFTEST(pse51_pthread_primitive_attr_profile,
                test_pse51_pthread_primitive_attr_profile);

/* SYS_THREAD_CREATE stays a strict two-argument ABI: it ignores a2 so
 * pre-existing callers that do not clear unused registers keep working.
 * SYS_THREAD_CREATE_EXPLICIT carries the opt-in explicit-priority
 * encoding in a2 so a libc pthread_create with PTHREAD_EXPLICIT_SCHED
 * can spawn at a non-default priority without the
 * SYS_THREAD_SETSCHEDPARAM race window. Encoding: a2 == 0 -> inherit,
 * a2 in [1, CONFIG_SCHED_NPRIO] -> explicit prio (a2 - 1).
 * Out-of-range -> EINVAL; raising above the creator's base priority
 * -> EPERM.
 *
 * The test passes u_entry = 0, which fails proc_vma_check_access with
 * EFAULT after the priority arm of the handler runs. That lets us
 * exercise the validation path without standing up an executable VMA
 * and a runnable stack.
 */
static i32 test_pse51_thread_create_prio_abi(void)
{
    struct proc *p;
    struct sched_task *td;
    struct trap_frame tf = {0};

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);

    /* Establish a known creator base priority so the privilege bound
     * has a non-trivial threshold to assert against.
     */
    td->td_base_prio = SCHED_PRIO_HIGH;

    tf.a7 = SYS_THREAD_CREATE;
    tf.a0 = 0;
    tf.a1 = 0;

    /* Historical ABI: a2 is ignored, even if it contains garbage. */
    tf.a2 = (u64) CONFIG_SCHED_NPRIO + 1;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EFAULT, 2);

    tf.a7 = SYS_THREAD_CREATE_EXPLICIT;

    /* a2 == 0: inherit; proc_vma_check_access fails first with EFAULT. */
    tf.a2 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EFAULT, 3);

    /* a2 == 1: explicit prio 0 (IDLE), passes prio check, falls through
     * to EFAULT for the same reason.
     */
    tf.a2 = 1;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EFAULT, 4);

    /* a2 = creator's base + 1: explicit prio == base, allowed. */
    tf.a2 = (u64) td->td_base_prio + 1;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EFAULT, 5);

    /* a2 = base + 2: explicit prio == base + 1, would raise above the
     * creator. EPERM gates this before the entry check.
     */
    if ((u64) td->td_base_prio + 2 <= (u64) CONFIG_SCHED_NPRIO) {
        tf.a2 = (u64) td->td_base_prio + 2;
        SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EPERM, 6);
    }

    /* a2 > CONFIG_SCHED_NPRIO: out of range. */
    tf.a2 = (u64) CONFIG_SCHED_NPRIO + 1;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 7);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_thread_create_prio_abi,
                test_pse51_thread_create_prio_abi);

static i32 test_pse51_signal_profile(void)
{
    struct proc *p;
    struct sched_task *td;
    struct trap_frame tf = {0};
    const vaddr_t va = USER_DATA_BASE + (183UL * PAGE_SIZE);
    u32 set = 0;
    u32 old_mask = 0;
    i32 signo_out = 0;
    u64 value_out = 0;

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);
    SELFTEST_ASSERT(pse51_map_user_page(p, va), 2);

    tf.a7 = SYS_SIGPROCMASK;
    set = sig_bit(SIGUSR1);
    SELFTEST_ASSERT(copy_to_user(va, &set, sizeof(set)) == 0, 3);
    tf.a0 = 99;
    tf.a1 = (u64) va;
    tf.a2 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 4);

    set = 0xFFFFFFFFu;
    SELFTEST_ASSERT(copy_to_user(va, &set, sizeof(set)) == 0, 5);
    tf.a0 = SIG_SETMASK;
    tf.a1 = (u64) va;
    tf.a2 = (u64) (va + sizeof(u32));
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 6);
    SELFTEST_ASSERT((td->td_sig.blocked & sig_bit(SIGKILL)) == 0, 7);
    SELFTEST_ASSERT(
        copy_from_user(&old_mask, va + sizeof(u32), sizeof(old_mask)) == 0, 8);

    tf.a7 = SYS_PTHREAD_KILL;
    tf.a0 = (u64) syscall_test_thread_token(p, td);
    tf.a1 = SIGUSR2;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 9);
    SELFTEST_ASSERT((td->td_sig.pending & sig_bit(SIGUSR2)) != 0, 10);
    SELFTEST_ASSERT((p->sig_state.proc_pending & sig_bit(SIGUSR2)) == 0, 11);

    td->td_sig.pending = 0;
    tf.a1 = SIGKILL;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 12);

    tf.a7 = SYS_SIGTIMEDWAIT;
    set = 0;
    SELFTEST_ASSERT(copy_to_user(va, &set, sizeof(set)) == 0, 13);
    tf.a0 = (u64) va;
    tf.a1 = 0;
    tf.a2 = 0;
    tf.a3 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 14);

    td->td_sig.pending = sig_bit(SIGUSR1) | sig_bit(SIGUSR2);
    set = sig_bit(SIGUSR2);
    SELFTEST_ASSERT(copy_to_user(va, &set, sizeof(set)) == 0, 15);
    tf.a1 = (u64) (va + sizeof(u32));
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == SIGUSR2, 16);
    SELFTEST_ASSERT(
        copy_from_user(&signo_out, va + sizeof(u32), sizeof(signo_out)) == 0,
        17);
    SELFTEST_ASSERT(signo_out == SIGUSR2, 18);

    td->td_sig.pending = 0;
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR1;
    tf.a2 = 0x1122334455667788ULL;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 19);
    SELFTEST_ASSERT((p->sig_state.proc_pending & sig_bit(SIGUSR1)) != 0, 20);

    set = sig_bit(SIGUSR1);
    SELFTEST_ASSERT(copy_to_user(va, &set, sizeof(set)) == 0, 21);
    tf.a7 = SYS_SIGTIMEDWAIT;
    tf.a0 = (u64) va;
    tf.a1 = (u64) (va + sizeof(u32));
    tf.a2 = 0;
    tf.a3 = (u64) (va + sizeof(u32) + sizeof(i32));
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == SIGUSR1, 22);
    SELFTEST_ASSERT(
        copy_from_user(&signo_out, va + sizeof(u32), sizeof(signo_out)) == 0,
        23);
    SELFTEST_ASSERT(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                                   sizeof(value_out)) == 0,
                    24);
    SELFTEST_ASSERT(signo_out == SIGUSR1, 25);
    SELFTEST_ASSERT(value_out == 0x1122334455667788ULL, 26);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_signal_profile, test_pse51_signal_profile);

static i32 test_pse51_timer_mqueue_profile(void)
{
    struct proc *p;
    struct sched_task *td;
    struct trap_frame tf = {0};
    const vaddr_t va = USER_DATA_BASE + (184UL * PAGE_SIZE);
    struct timespec ts = {0};
    char msg[] = "mazu";
    char recv[8] = {0};
    u32 prio = 0;
    i64 timer_h;
    i64 mq_h;

    SELFTEST_ASSERT(alloc_proc_and_task(&p, &td), 1);
    SELFTEST_ASSERT(pse51_map_user_page(p, va), 2);

    tf.a7 = SYS_TIMER_CREATE;
    timer_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(timer_h >= 0, 3);

    tf.a7 = SYS_TIMER_SETTIME;
    tf.a0 = (u64) timer_h;
    tf.a1 = 10;
    tf.a2 = 0;
    tf.a3 = 0;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 4);

    tf.a7 = SYS_TIMER_GETTIME;
    tf.a0 = (u64) timer_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) >= 0, 5);

    tf.a7 = SYS_TIMER_GETOVERRUN;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) >= 0, 6);

    tf.a7 = SYS_TIMER_DELETE;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 7);

    tf.a7 = SYS_TIMER_GETTIME;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) EINVAL, 8);

    tf.a7 = SYS_MQ_OPEN;
    tf.a0 = 1;
    tf.a1 = sizeof(recv);
    mq_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(mq_h >= 0, 9);

    SELFTEST_ASSERT(copy_to_user(va, msg, sizeof(msg)) == 0, 10);
    tf.a7 = SYS_MQ_SEND;
    tf.a0 = (u64) mq_h;
    tf.a1 = (u64) va;
    tf.a2 = sizeof(msg);
    tf.a3 = 7;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 11);

    tf.a7 = SYS_MQ_RECEIVE;
    tf.a0 = (u64) mq_h;
    tf.a1 = (u64) (va + 16);
    tf.a2 = sizeof(recv);
    tf.a3 = (u64) (va + 32);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == (i64) sizeof(msg), 12);
    SELFTEST_ASSERT(copy_from_user(recv, va + 16, sizeof(msg)) == 0, 13);
    SELFTEST_ASSERT(copy_from_user(&prio, va + 32, sizeof(prio)) == 0, 14);
    SELFTEST_ASSERT(recv[0] == 'm' && recv[1] == 'a' && recv[2] == 'z' &&
                        recv[3] == 'u' && recv[4] == '\0',
                    15);
    SELFTEST_ASSERT(prio == 7, 16);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va + 48, &ts, sizeof(ts)) == 0, 17);
    tf.a7 = SYS_MQ_TIMEDRECEIVE;
    tf.a0 = (u64) mq_h;
    tf.a1 = (u64) (va + 16);
    tf.a2 = sizeof(recv);
    tf.a3 = 0;
    tf.a4 = (u64) (va + 48);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 18);

    SELFTEST_ASSERT(copy_to_user(va, msg, sizeof(msg)) == 0, 19);
    tf.a7 = SYS_MQ_SEND;
    tf.a0 = (u64) mq_h;
    tf.a1 = (u64) va;
    tf.a2 = sizeof(msg);
    tf.a3 = 1;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 20);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va + 48, &ts, sizeof(ts)) == 0, 21);
    tf.a7 = SYS_MQ_TIMEDSEND;
    tf.a0 = (u64) mq_h;
    tf.a1 = (u64) va;
    tf.a2 = sizeof(msg);
    tf.a3 = 2;
    tf.a4 = (u64) (va + 48);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 22);

    tf.a7 = SYS_MQ_RECEIVE;
    tf.a0 = (u64) mq_h;
    tf.a1 = (u64) (va + 16);
    tf.a2 = sizeof(recv);
    tf.a3 = (u64) (va + 32);
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == (i64) sizeof(msg), 23);

    tf.a7 = SYS_MQ_CLOSE;
    tf.a0 = (u64) mq_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 24);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_timer_mqueue_profile, test_pse51_timer_mqueue_profile);
