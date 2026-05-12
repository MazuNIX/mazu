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
    SELFTEST_ASSERT(sys_sysconf_query(_SC_CLOCK_SELECTION) == -1, 14);
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

    tf.a7 = SYS_COND_INIT;
    cond_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(cond_h >= 0, 8);

    tf.a7 = SYS_COND_SIGNAL;
    tf.a0 = (u64) cond_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 9);

    tf.a7 = SYS_COND_BROADCAST;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 10);

    tf.a7 = SYS_SEM_INIT;
    tf.a0 = 1;
    sem_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(sem_h >= 0, 11);

    tf.a7 = SYS_SEM_WAIT;
    tf.a0 = (u64) sem_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 12);

    tf.a7 = SYS_SEM_POST;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 13);

    tf.a7 = SYS_SEM_TRYWAIT;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 14);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 15);
    tf.a7 = SYS_SEM_TIMEDWAIT;
    tf.a0 = (u64) sem_h;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 16);

    tf.a7 = SYS_BARRIER_INIT;
    tf.a0 = 1;
    barrier_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(barrier_h >= 0, 17);

    tf.a7 = SYS_BARRIER_WAIT;
    tf.a0 = (u64) barrier_h;
    SELFTEST_ASSERT(
        syscall_dispatch(&tf, td) == (i64) PTHREAD_BARRIER_SERIAL_THREAD, 18);

    tf.a7 = SYS_BARRIER_DESTROY;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 19);

    tf.a7 = SYS_RWLOCK_INIT;
    rwlock_h = syscall_dispatch(&tf, td);
    SELFTEST_ASSERT(rwlock_h >= 0, 20);

    tf.a7 = SYS_RWLOCK_RDLOCK;
    tf.a0 = (u64) rwlock_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 21);

    tf.a7 = SYS_RWLOCK_UNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 22);

    tf.a7 = SYS_RWLOCK_TRYWRLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 23);

    tf.a7 = SYS_RWLOCK_UNLOCK;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 24);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    SELFTEST_ASSERT(copy_to_user(va, &ts, sizeof(ts)) == 0, 25);
    tf.a7 = SYS_RWLOCK_TIMEDRDLOCK;
    tf.a0 = (u64) rwlock_h;
    tf.a1 = (u64) va;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == -(i64) ETIMEDOUT, 26);

    tf.a7 = SYS_RWLOCK_DESTROY;
    tf.a0 = (u64) rwlock_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 27);

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
    tf.a0 = 4;
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

    tf.a7 = SYS_MQ_CLOSE;
    tf.a0 = (u64) mq_h;
    SELFTEST_ASSERT(syscall_dispatch(&tf, td) == 0, 19);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pse51_timer_mqueue_profile, test_pse51_timer_mqueue_profile);
