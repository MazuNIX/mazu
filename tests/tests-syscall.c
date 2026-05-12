/* SPDX-License-Identifier: MIT */
#include <kernel/ipc/mqueue.h>
#include <kernel/sync/sync_handle.h>
#include <mazu/cap.h>
#include <mazu/selftest.h>
#include <mazu/syscall.h>
#include <mazu/uaccess.h>
#include <mazu/vfs.h>
#include "../kernel/sync/futex.h"
#include "tests-proc-helpers.h"

static bool syscall_test_vfs_available(void)
{
    struct result_vfs_file f = vfs_open(STR("/hello.txt"));
    if (f.is_error)
        return false;
    struct vfs_file vf = result_vfs_file_checked(f);
    vfs_close(&vf);
    return true;
}

static i32 selftest_sys_open_emfile(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Fill all FD slots so sys_open returns EMFILE. */
    for (sz i = PROC_FD_STDERR + 1; i < CAP_SPACE_SLOTS - PROC_THREAD_MAX; i++)
        assert(cap_dup_fd(p, PROC_FD_STDOUT, (i32) i, true) == (i32) i);

    struct trap_frame tf = {0};
    tf.a0 = USER_CODE_BASE;
    tf.a1 = 4;
    assert(sys_open(&tf, td) == -(i64) EMFILE);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_open_emfile, selftest_sys_open_emfile);

static i32 selftest_sys_open_mints_non_grant_fd(void)
{
    if (!syscall_test_vfs_available())
        return 0;

    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const char path[] = "/hello.txt";
    const vaddr_t va = USER_DATA_BASE + (137UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);
    assert(copy_to_user(va, path, sizeof(path)) == 0);

    struct trap_frame tf = {0};
    tf.a0 = va;
    tf.a1 = sizeof(path) - 1;
    i64 fd = sys_open(&tf, td);
    assert(fd >= 0);
    assert(!cap_fd_has_rights(p, (i32) fd, CAP_RIGHT_GRANT));

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_open_mints_non_grant_fd,
                selftest_sys_open_mints_non_grant_fd);

static i32 selftest_sys_mq_open_emfile_rollback(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    for (i32 fd = PROC_FD_STDERR + 1; fd < CAP_SPACE_SLOTS - PROC_THREAD_MAX;
         fd++)
        assert(cap_dup_fd(p, PROC_FD_STDOUT, fd, true) == fd);

    struct trap_frame tf = {0};
    tf.a0 = 4;
    tf.a1 = 8;
    assert(sys_mq_open(&tf, td) == -(i64) EMFILE);

    i32 handles[MQ_MAX_QUEUES];
    for (i32 i = 0; i < MQ_MAX_QUEUES; i++) {
        handles[i] = mqueue_open(NULL, 4, 8);
        assert(handles[i] >= 0);
    }
    assert(mqueue_open(NULL, 4, 8) == -(i32) EAGAIN);
    for (i32 i = 0; i < MQ_MAX_QUEUES; i++)
        assert(mqueue_close(handles[i]) == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_mq_open_emfile_rollback,
                selftest_sys_mq_open_emfile_rollback);

static i32 selftest_sys_mutex_init_emfile_rollback(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    for (i32 fd = PROC_FD_STDERR + 1; fd < CAP_SPACE_SLOTS - PROC_THREAD_MAX;
         fd++)
        assert(cap_dup_fd(p, PROC_FD_STDOUT, fd, true) == fd);

    struct trap_frame tf = {0};
    tf.a7 = SYS_MUTEX_INIT;
    assert(syscall_dispatch(&tf, td) == -(i64) EMFILE);

    i32 handles[SYNC_MAX_MUTEXES];
    for (i32 i = 0; i < SYNC_MAX_MUTEXES; i++) {
        handles[i] = sync_mutex_alloc(NULL);
        assert(handles[i] >= 0);
    }
    assert(sync_mutex_alloc(NULL) == -(i32) EAGAIN);
    for (i32 i = 0; i < SYNC_MAX_MUTEXES; i++)
        sync_mutex_put_idx(handles[i]);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_mutex_init_emfile_rollback,
                selftest_sys_mutex_init_emfile_rollback);

static i32 selftest_sys_exit_frees_proc_slot(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));
    u16 pid = p->pid;

    struct trap_frame tf = {0};
    tf.a0 = 7;

    assert(sys_exit(&tf, td) == 0);
    assert(td->state == TD_STATE_TERMINATING);
    assert(td->proc == NULL);
    /* Orphan auto-reap: parent_pid=0, no parent exists -> freed. */
    assert(proc_find(pid) == NULL);
    free_mock_task(td);
    return 0;
}
DEFINE_SELFTEST(sys_exit_frees_proc_slot, selftest_sys_exit_frees_proc_slot);

static i32 selftest_syscall_enosys(void)
{
    struct trap_frame tf = {0};
    tf.a7 = SYS_NR + 5; /* out of range */
    assert(syscall_dispatch(&tf, NULL) == -(i64) ENOSYS);
    return 0;
}
DEFINE_SELFTEST(syscall_enosys, selftest_syscall_enosys);

static i32 selftest_syscall_needs_proc(void)
{
    struct sched_task *td = alloc_mock_task();
    assert(td);
    td->proc = NULL; /* no process */

    struct trap_frame tf = {0};
    tf.a7 = SYS_OPEN; /* requires NEEDS_PROC */
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    free_mock_task(td);
    return 0;
}
DEFINE_SELFTEST(syscall_needs_proc, selftest_syscall_needs_proc);

static i32 selftest_syscall_needs_proc_new_handlers(void)
{
    struct sched_task *td = alloc_mock_task();
    assert(td);
    td->proc = NULL;

    struct trap_frame tf = {0};

    tf.a7 = SYS_MUTEX_INIT;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    tf.a7 = SYS_BARRIER_INIT;
    tf.a0 = 2;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    tf.a7 = SYS_RWLOCK_INIT;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    tf.a7 = SYS_MQ_OPEN;
    tf.a0 = 1;
    tf.a1 = 16;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    tf.a7 = SYS_TIMER_SETTIME;
    tf.a0 = 0;
    tf.a1 = 1;
    tf.a2 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    tf.a7 = SYS_SCHED_SETAFFINITY;
    tf.a0 = 0;
    tf.a1 = -1;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    tf.a7 = SYS_SCHED_GETAFFINITY;
    tf.a0 = 0;
    tf.a1 = USER_CODE_BASE;
    assert(syscall_dispatch(&tf, td) == -(i64) EPERM);

    free_mock_task(td);
    return 0;
}
DEFINE_SELFTEST(syscall_needs_proc_new_handlers,
                selftest_syscall_needs_proc_new_handlers);

static i32 selftest_robust_pending_without_head(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (137UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    ptr next = 0;
    u32 futex_word = 123;
    assert(copy_to_user(va, &next, sizeof(next)) == 0);
    assert(copy_to_user(va + sizeof(ptr), &futex_word, sizeof(futex_word)) ==
           0);

    td->td_robust_list_head = 0;
    td->td_robust_futex_offset = (i32) sizeof(ptr);
    td->td_robust_pending = va;

    futex_exit_robust_list_task(td);

    u32 out = U32_MAX;
    assert(copy_from_user(&out, va + sizeof(ptr), sizeof(out)) == 0);
    assert(out == 0x40000000U);
    assert(td->td_robust_list_head == 0);
    assert(td->td_robust_futex_offset == 0);
    assert(td->td_robust_pending == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(robust_pending_without_head,
                selftest_robust_pending_without_head);

static i32 selftest_syscall_allow_mask(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Allow only SYS_EXIT and SYS_YIELD. */
    p->syscall_allow[0] = BIT(SYS_EXIT) | BIT(SYS_YIELD);

    struct trap_frame tf = {0};

    /* SYS_OPEN should be denied (not in allow mask). */
    tf.a7 = SYS_OPEN;
    assert(syscall_dispatch(&tf, td) == -(i64) EACCES);

    /* SYS_YIELD should be allowed. */
    tf.a7 = SYS_YIELD;
    assert(syscall_dispatch(&tf, td) == 0);

    /* SYS_EXIT terminates, so test it last. */
    tf.a7 = SYS_EXIT;
    tf.a0 = 0;
    assert(syscall_dispatch(&tf, td) == 0);

    free_mock_task(td);
    return 0;
}
DEFINE_SELFTEST(syscall_allow_mask, selftest_syscall_allow_mask);

static i32 selftest_syscall_allow_mask_high_numbers(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    p->syscall_allow[1] = BIT(SYS_TIMER_GETTIME - 64);

    struct trap_frame tf = {0};
    tf.a7 = SYS_TIMER_GETTIME;
    tf.a0 = -1;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    tf.a7 = SYS_THREAD_SELF;
    assert(syscall_dispatch(&tf, td) == -(i64) EACCES);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(syscall_allow_mask_high_numbers,
                selftest_syscall_allow_mask_high_numbers);

static i32 selftest_timer_invalid_handles(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};

    tf.a7 = SYS_TIMER_GETTIME;
    tf.a0 = (u64) -1;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    tf.a7 = SYS_TIMER_GETOVERRUN;
    tf.a0 = (u64) -1;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(timer_invalid_handles, selftest_timer_invalid_handles);

static i32 selftest_syscall_security_stats(void)
{
    struct syscall_security_stats before = syscall_security_stats_get();

    /* Trigger ENOSYS counter. */
    struct trap_frame tf = {0};
    tf.a7 = SYS_NR + 1;
    syscall_dispatch(&tf, NULL);

    struct syscall_security_stats after = syscall_security_stats_get();
    assert(after.nr_enosys > before.nr_enosys);

    /* Trigger nr_denied counter via allow-list denial. */
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));
    p->syscall_allow[0] = BIT(SYS_EXIT);

    before = syscall_security_stats_get();
    tf.a7 = SYS_YIELD; /* not in allow mask -> EACCES -> nr_denied++ */
    syscall_dispatch(&tf, td);
    after = syscall_security_stats_get();
    assert(after.nr_denied > before.nr_denied);

    /* Cleanup. */
    p->syscall_allow[0] = 0;
    p->syscall_allow[1] = 0;
    tf.a7 = SYS_EXIT;
    tf.a0 = 0;
    syscall_dispatch(&tf, td);
    free_mock_task(td);
    return 0;
}
DEFINE_SELFTEST(syscall_security_stats, selftest_syscall_security_stats);

static i32 selftest_syscall_unrestricted(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));
    assert(p->syscall_allow[0] == 0 && p->syscall_allow[1] == 0);

    struct trap_frame tf = {0};

    /* All syscalls should be allowed when mask is 0. */
    tf.a7 = SYS_YIELD;
    assert(syscall_dispatch(&tf, td) == 0);
    tf.a7 = SYS_TIME;
    assert(syscall_dispatch(&tf, td) >= 0);

    tf.a7 = SYS_EXIT;
    tf.a0 = 0;
    syscall_dispatch(&tf, td);
    free_mock_task(td);
    return 0;
}
DEFINE_SELFTEST(syscall_unrestricted, selftest_syscall_unrestricted);

static i32 selftest_sys_getpid(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};
    tf.a7 = SYS_GETPID;
    i64 pid = syscall_dispatch(&tf, td);
    assert(pid == (i64) p->pid);
    assert(pid > 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_getpid, selftest_sys_getpid);

static i32 selftest_sys_getppid(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));
    p->parent_pid = 42;

    struct trap_frame tf = {0};
    tf.a7 = SYS_GETPPID;
    i64 ppid = syscall_dispatch(&tf, td);
    assert(ppid == 42);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_getppid, selftest_sys_getppid);

static i32 selftest_sys_dup(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* stdout (FD 1) is open; dup it. Lowest free is FD 3. */
    struct trap_frame tf = {0};
    tf.a7 = SYS_DUP;
    tf.a0 = PROC_FD_STDOUT;
    i64 newfd = syscall_dispatch(&tf, td);
    assert(newfd == 3);
    assert(cap_fd_is_valid(p, 3));

    /* Dup again; should get FD 4. */
    tf.a0 = PROC_FD_STDOUT;
    newfd = syscall_dispatch(&tf, td);
    assert(newfd == 4);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_dup, selftest_sys_dup);

static i32 selftest_sys_dup_ebadf(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};
    tf.a7 = SYS_DUP;
    tf.a0 = 10; /* FD 10 is not open */
    assert(syscall_dispatch(&tf, td) == -(i64) EBADF);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_dup_ebadf, selftest_sys_dup_ebadf);

static i32 selftest_sys_dup2(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* dup2(stdout, 5) - FD 5 was closed, now open. */
    struct trap_frame tf = {0};
    tf.a7 = SYS_DUP2;
    tf.a0 = PROC_FD_STDOUT;
    tf.a1 = 5;
    i64 rc = syscall_dispatch(&tf, td);
    assert(rc == 5);
    assert(cap_fd_is_valid(p, 5));

    /* dup2(stdout, stdout) is a no-op, returns stdout. */
    tf.a0 = PROC_FD_STDOUT;
    tf.a1 = PROC_FD_STDOUT;
    rc = syscall_dispatch(&tf, td);
    assert(rc == PROC_FD_STDOUT);

    /* dup2 to a reserved CAP_TYPE_THREAD slot must fail without
     * destroying the live thread handle stored there.
     */
    i64 thread_token = syscall_test_thread_token(p, td);
    assert(thread_token > 0);
    tf.a0 = PROC_FD_STDOUT;
    tf.a1 = td->td_cap_slot;
    rc = syscall_dispatch(&tf, td);
    assert(rc == -(i64) EBADF);
    assert(syscall_test_thread_token(p, td) == thread_token);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_dup2, selftest_sys_dup2);

static i32 selftest_sys_lseek(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    if (!syscall_test_vfs_available()) {
        free_proc_and_task(p, td);
        return 0;
    }

    i32 fd = 3;
    struct result_vfs_file fres = vfs_open(STR("/hello.txt"));
    assert(!fres.is_error);
    assert(cap_open_vfs(p, result_vfs_file_checked(fres),
                        CAP_RIGHT_READ | CAP_RIGHT_WRITE, true, fd,
                        true) == fd);

    /* SEEK_SET to position 10. */
    struct trap_frame tf = {0};
    tf.a0 = (u64) fd;
    tf.a1 = 10;
    tf.a2 = SEEK_SET;
    i64 pos = sys_lseek(&tf, td);
    assert(pos == 10);
    struct cap_ref ref = cap_lookup_fd(p, fd, 0);
    assert(ref.ptr);
    assert(((struct fd_pool_entry *) ref.ptr)->offset == 10);
    cap_put_ref(&ref);

    /* SEEK_CUR +5 -> position 15. */
    tf.a1 = 5;
    tf.a2 = SEEK_CUR;
    pos = sys_lseek(&tf, td);
    assert(pos == 15);

    /* SEEK_SET negative -> EINVAL. */
    tf.a1 = (u64) (i64) -1;
    tf.a2 = SEEK_SET;
    assert(sys_lseek(&tf, td) == -(i64) EINVAL);

    /* Console FDs are not seekable -> ESPIPE. */
    tf.a0 = PROC_FD_STDOUT;
    tf.a1 = 0;
    tf.a2 = SEEK_SET;
    assert(sys_lseek(&tf, td) == -(i64) ESPIPE);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_lseek, selftest_sys_lseek);

/* sys_chdir and sys_getcwd use copy_from_user/copy_to_user, which reject
 * kernel pointers in S-mode selftests.  Test the core logic by:
 * (1) verifying initial cwd state, (2) directly manipulating cwd to
 * simulate chdir, (3) verifying getcwd ERANGE boundary.
 */

static i32 selftest_sys_chdir_getcwd(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Initial cwd is "/". */
    assert(p->cwd_len == 1);
    assert(p->cwd[0] == '/');

    /* Simulate chdir: directly set cwd as sys_chdir would after
     * VFS validation and copy_user_path succeed.
     */
    const char *newcwd = "/web";
    sz newlen = 4;
    memcpy(p->cwd, newcwd, newlen);
    p->cwd_len = newlen;
    assert(p->cwd[0] == '/' && p->cwd[1] == 'w');

    /* getcwd boundary: size < cwd_len+1 should produce ERANGE
     * (POSIX requires space for NUL terminator). cwd_len=4 ("/web"),
     * so need size >= 5.
     */
    struct trap_frame tf = {0};
    tf.a0 = 0; /* NULL buffer - never reached due to size check */
    tf.a1 = 0; /* size = 0 */
    assert(sys_getcwd(&tf, td) == -(i64) ERANGE);

    tf.a1 = 4; /* exactly cwd_len, still needs +1 for NUL */
    assert(sys_getcwd(&tf, td) == -(i64) ERANGE);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_chdir_getcwd, selftest_sys_chdir_getcwd);

/* sysconf tests: call sys_sysconf_query() directly. */

static i32 selftest_sysconf_page_size(void)
{
    assert(sys_sysconf_query(_SC_PAGE_SIZE) == (i64) PAGE_SIZE);
    assert(sys_sysconf_query(_SC_PAGESIZE) == (i64) PAGE_SIZE);
    return 0;
}
DEFINE_SELFTEST(sysconf_page_size, selftest_sysconf_page_size);

static i32 selftest_sysconf_open_max(void)
{
    assert(sys_sysconf_query(_SC_OPEN_MAX) == (i64) PROC_FD_MAX);
    return 0;
}
DEFINE_SELFTEST(sysconf_open_max, selftest_sysconf_open_max);

static i32 selftest_sysconf_nproc(void)
{
    assert(sys_sysconf_query(_SC_NPROCESSORS_CONF) == (i64) nr_cpus_online);
    assert(sys_sysconf_query(_SC_NPROCESSORS_ONLN) == (i64) nr_cpus_online);
    return 0;
}
DEFINE_SELFTEST(sysconf_nproc, selftest_sysconf_nproc);

static i32 selftest_sysconf_pipe_buf(void)
{
    assert(sys_sysconf_query(_SC_PIPE_BUF) == (i64) PIPE_BUF_SIZE);
    return 0;
}
DEFINE_SELFTEST(sysconf_pipe_buf, selftest_sysconf_pipe_buf);

static i32 selftest_sysconf_child_max(void)
{
    assert(sys_sysconf_query(_SC_CHILD_MAX) == (i64) (PROC_MAX - 1));
    return 0;
}
DEFINE_SELFTEST(sysconf_child_max, selftest_sysconf_child_max);

static i32 selftest_sysconf_invalid(void)
{
    assert(sys_sysconf_query(9999) == -(i64) EINVAL);
    assert(sys_sysconf_query(-1) == -(i64) EINVAL);
    return 0;
}
DEFINE_SELFTEST(sysconf_invalid, selftest_sysconf_invalid);

/* PSE51 option reporting: present features advertise their
 * _POSIX_* feature-test value, absent features return -1.
 */
static i32 selftest_sysconf_pse51_present(void)
{
    assert(_POSIX_FSYNC == 200809L);
    assert(sys_sysconf_query(_SC_TIMERS) == _POSIX_TIMERS);
    assert(sys_sysconf_query(_SC_MONOTONIC_CLOCK) == _POSIX_MONOTONIC_CLOCK);
    assert(sys_sysconf_query(_SC_PRIORITY_SCHEDULING) ==
           _POSIX_PRIORITY_SCHEDULING);
    assert(sys_sysconf_query(_SC_SEMAPHORES) == _POSIX_SEMAPHORES);
    assert(sys_sysconf_query(_SC_BARRIERS) == _POSIX_BARRIERS);
    assert(sys_sysconf_query(_SC_READER_WRITER_LOCKS) ==
           _POSIX_READER_WRITER_LOCKS);
    assert(sys_sysconf_query(_SC_THREAD_PRIORITY_INHERIT) ==
           _POSIX_THREAD_PRIO_INHERIT);
    assert(sys_sysconf_query(_SC_MESSAGE_PASSING) == _POSIX_MESSAGE_PASSING);
    assert(sys_sysconf_query(_SC_THREADS) == _POSIX_THREADS);
    assert(sys_sysconf_query(_SC_THREAD_CPUTIME) == _POSIX_THREAD_CPUTIME);
    assert(sys_sysconf_query(_SC_CPUTIME) == _POSIX_CPUTIME);
    assert(sys_sysconf_query(_SC_REALTIME_SIGNALS) == _POSIX_REALTIME_SIGNALS);
    return 0;
}
DEFINE_SELFTEST(sysconf_pse51_present, selftest_sysconf_pse51_present);

static i32 selftest_sysconf_pse51_absent(void)
{
    /* Features intentionally absent: option reporting must return -1
     * (POSIX-style "absent") rather than -EINVAL. _SC_SPIN_LOCKS is
     * here because the userspace pthread_spin_* surface is not
     * exposed; advertising the macro would let an app gate on
     * _POSIX_SPIN_LOCKS and call absent APIs. _SC_CLOCK_SELECTION
     * is absent because clock_nanosleep is not exposed.
     */
    assert(sys_sysconf_query(_SC_SPIN_LOCKS) == -1);
    assert(sys_sysconf_query(_SC_CLOCK_SELECTION) == -1);
    return 0;
}
DEFINE_SELFTEST(sysconf_pse51_absent, selftest_sysconf_pse51_absent);

/* SYS_NANOSLEEP argument validation: the kernel rejects bad timespec
 * values with EINVAL before calling into sleep_ms.  The EINTR remainder
 * path is exercised in higher-level integration tests because
 * deterministically interrupting sleep_ms from a selftest task requires
 * cross-task signal delivery.
 */
static i32 selftest_nanosleep_einval(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Map a user page for the timespec.  Use the same pattern as
     * selftest_sys_sched_getaffinity_success: a page in the user data
     * region with PT-flag permissions.
     */
    const vaddr_t va = USER_DATA_BASE + (130UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_NANOSLEEP;
    tf.a0 = (u64) va;
    tf.a1 = 0;

    /* Negative tv_sec. */
    struct timespec bad = {.tv_sec = -1, .tv_nsec = 0};
    assert(copy_to_user(va, &bad, sizeof(bad)) == 0);
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Negative tv_nsec. */
    bad.tv_sec = 0;
    bad.tv_nsec = -1;
    assert(copy_to_user(va, &bad, sizeof(bad)) == 0);
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* tv_nsec >= NSEC_PER_SEC. */
    bad.tv_sec = 0;
    bad.tv_nsec = (i64) NSEC_PER_SEC;
    assert(copy_to_user(va, &bad, sizeof(bad)) == 0);
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* tv_sec near INT64_MAX must not be allowed to overflow the ns/ms
     * conversions. The kernel caps tv_sec at U64_MAX / NSEC_PER_SEC; any
     * value above that returns EINVAL.
     */
    bad.tv_sec = I64_MAX;
    bad.tv_nsec = 0;
    assert(copy_to_user(va, &bad, sizeof(bad)) == 0);
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(nanosleep_einval, selftest_nanosleep_einval);

/* mlock / munlock no-op coverage: argument validation runs but the
 * page tables are untouched.
 */
static i32 selftest_mlock_munlock(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Map a page so user_addr_valid succeeds for a real range. */
    const vaddr_t va = USER_DATA_BASE + (131UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};

    /* Empty range -> EINVAL. */
    tf.a7 = SYS_MLOCK;
    tf.a0 = (u64) va;
    tf.a1 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);
    tf.a7 = SYS_MUNLOCK;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Wrap-around -> EINVAL. */
    tf.a7 = SYS_MLOCK;
    tf.a0 = U64_MAX - 16;
    tf.a1 = 64;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Range outside any user VMA -> ENOMEM. */
    tf.a7 = SYS_MLOCK;
    tf.a0 = 0;
    tf.a1 = 16;
    assert(syscall_dispatch(&tf, td) == -(i64) ENOMEM);

    /* Valid range inside user space -> success. proc_map_user_page does
     * not register a VMA, so the VMA portion of user_addr_valid is
     * skipped (n_vmas == 0); the handler still exercises the bounds,
     * non-empty, and non-wrap checks plus the page-table walk.
     */
    tf.a7 = SYS_MLOCK;
    tf.a0 = (u64) va;
    tf.a1 = 16;
    assert(syscall_dispatch(&tf, td) == 0);
    tf.a7 = SYS_MUNLOCK;
    assert(syscall_dispatch(&tf, td) == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(mlock_munlock, selftest_mlock_munlock);

/* fsync / fdatasync validate the FD is open and return success;
 * Mazu has no separate sync path because SFS already commits
 * synchronously and synthetic/ram filesystems have no backing store.
 */
static i32 selftest_fsync_fdatasync(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};

    /* Bad FD -> EBADF. */
    tf.a7 = SYS_FSYNC;
    tf.a0 = (u64) -1;
    assert(syscall_dispatch(&tf, td) == -(i64) EBADF);
    tf.a7 = SYS_FDATASYNC;
    assert(syscall_dispatch(&tf, td) == -(i64) EBADF);

    /* Out-of-range FD -> EBADF. */
    tf.a7 = SYS_FSYNC;
    tf.a0 = (u64) PROC_FD_MAX;
    assert(syscall_dispatch(&tf, td) == -(i64) EBADF);

    /* Closed but in-range FD -> EBADF. */
    tf.a7 = SYS_FSYNC;
    tf.a0 = PROC_FD_STDERR + 1;
    assert(!cap_fd_is_valid(p, PROC_FD_STDERR + 1));
    assert(syscall_dispatch(&tf, td) == -(i64) EBADF);

    /* Open FD (stdout) -> success. */
    tf.a7 = SYS_FSYNC;
    tf.a0 = PROC_FD_STDOUT;
    assert(syscall_dispatch(&tf, td) == 0);
    tf.a7 = SYS_FDATASYNC;
    assert(syscall_dispatch(&tf, td) == 0);

    /* Pipe FD -> EINVAL (POSIX: fsync on a non-syncable file type). */
    struct pipe *pipe = pipe_alloc();
    assert(pipe);
    assert(cap_open_pipe(p, pipe, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT,
                         PROC_FD_STDIN, true) == PROC_FD_STDIN);
    tf.a7 = SYS_FSYNC;
    tf.a0 = PROC_FD_STDIN;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);
    tf.a7 = SYS_FDATASYNC;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(fsync_fdatasync, selftest_fsync_fdatasync);

/* sigprocmask: SIG_BLOCK / SIG_UNBLOCK / SIG_SETMASK update the
 * calling thread's blocked mask under sig_lock; SIGKILL cannot be
 * blocked.
 *
 * Coverage limitation: with PROC_THREAD_MAX == 1 there is exactly one
 * thread per proc, so this test cannot distinguish per-thread storage
 * from per-process storage. A true test of state isolation between
 * threads only becomes possible once SYS_THREAD_CREATE lands; at that
 * point this test must be extended to spawn a second thread, mutate
 * thread A's mask, and assert thread B's mask is unchanged.
 */
static i32 selftest_sigprocmask(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Map a page for set / oldset. */
    const vaddr_t va = USER_DATA_BASE + (132UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGPROCMASK;

    /* Invalid how -> EINVAL. */
    u32 set = 0xFFu;
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = 99;
    tf.a1 = (u64) va;
    tf.a2 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* SIG_SETMASK with all bits, including SIGKILL: SIGKILL gets
     * masked off internally but the call still succeeds.
     */
    set = 0xFFFFFFFFu;
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = SIG_SETMASK;
    tf.a1 = (u64) va;
    tf.a2 = 0;
    assert(syscall_dispatch(&tf, td) == 0);
    assert((td->td_sig.blocked & sig_bit(SIGKILL)) == 0);
    assert((td->td_sig.blocked & sig_bit(SIGTERM)) != 0);

    /* SIG_UNBLOCK clears the bits. */
    set = sig_bit(SIGTERM);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = SIG_UNBLOCK;
    assert(syscall_dispatch(&tf, td) == 0);
    assert((td->td_sig.blocked & sig_bit(SIGTERM)) == 0);

    /* SIG_BLOCK ORs new bits onto existing ones. Start with one bit
     * set, ask to block another, verify both are now set.
     */
    td->td_sig.blocked = sig_bit(SIGUSR1);
    set = sig_bit(SIGTERM);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = SIG_BLOCK;
    tf.a1 = (u64) va;
    tf.a2 = 0;
    assert(syscall_dispatch(&tf, td) == 0);
    assert((td->td_sig.blocked & sig_bit(SIGUSR1)) != 0);
    assert((td->td_sig.blocked & sig_bit(SIGTERM)) != 0);

    /* Bad u_old pointer must NOT mutate the mask: pre-validation
     * happens before lock acquisition. Save the mask, attempt with
     * a bad oldset pointer, verify it failed with EFAULT and the
     * mask is unchanged.
     */
    u32 saved = td->td_sig.blocked;
    set = sig_bit(SIGCHLD);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = SIG_SETMASK;
    tf.a1 = (u64) va;
    tf.a2 = 0xDEADBEEFUL; /* bad user pointer */
    assert(syscall_dispatch(&tf, td) == -(i64) EFAULT);
    assert(td->td_sig.blocked == saved);

    /* Read-only query (set == NULL) ignores how and returns the current
     * mask via oldset, matching POSIX query-only semantics.
     */
    td->td_sig.blocked = sig_bit(SIGUSR1);
    tf.a0 = 0;
    tf.a1 = 0;
    tf.a2 = (u64) va;
    assert(syscall_dispatch(&tf, td) == 0);
    u32 old = 0;
    assert(copy_from_user(&old, va, sizeof(old)) == 0);
    assert(old == sig_bit(SIGUSR1));
    assert(td->td_sig.blocked == sig_bit(SIGUSR1));

    /* Reset for cleanup. */
    td->td_sig.blocked = 0;
    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigprocmask, selftest_sigprocmask);

static i32 selftest_sys_sched_setaffinity(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* pid=0 means self: pin to hart 0. */
    struct trap_frame tf = {0};
    tf.a7 = SYS_SCHED_SETAFFINITY;
    tf.a0 = 0; /* self */
    tf.a1 = 0; /* hart 0 */
    assert(syscall_dispatch(&tf, td) == 0);
    assert(__atomic_load_n(&td->td_affinity, __ATOMIC_ACQUIRE) == 0);

    /* Reset to any. */
    tf.a1 = (u64) (i64) -1;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(__atomic_load_n(&td->td_affinity, __ATOMIC_ACQUIRE) == -1);

    /* Invalid hart -> EINVAL. */
    tf.a1 = (u64) 9999;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Overflow: pid exceeds u16 range -> EINVAL. */
    tf.a0 = (u64) U16_MAX + 1;
    tf.a1 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_sched_setaffinity, selftest_sys_sched_setaffinity);

/* sys_sched_getaffinity uses copy_to_user, which rejects kernel pointers
 * in S-mode selftests.  Verify the core logic by checking td_affinity
 * directly after setaffinity, and test getaffinity error paths.
 */
static i32 selftest_sys_sched_getaffinity_errors(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};
    tf.a7 = SYS_SCHED_GETAFFINITY;

    /* Overflow: pid exceeds u16 range -> EINVAL. */
    tf.a0 = (u64) U16_MAX + 1;
    tf.a1 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Bad pid -> ESRCH. */
    tf.a0 = (u64) U16_MAX;  /* unlikely to exist */
    tf.a1 = USER_CODE_BASE; /* valid user address */
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_sched_getaffinity_errors,
                selftest_sys_sched_getaffinity_errors);

static i32 selftest_sys_sched_getaffinity_success(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t user_out = USER_DATA_BASE + (129UL * PAGE_SIZE);
    assert(
        proc_map_user_page(p, user_out, PT_FLAG_RW | PT_FLAG_USER).is_error ==
        false);

    __atomic_store_n(&td->td_affinity, 2, __ATOMIC_RELEASE);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SCHED_GETAFFINITY;
    tf.a0 = 0;
    tf.a1 = user_out;
    assert(syscall_dispatch(&tf, td) == 0);

    i32 affinity = -1;
    assert(copy_from_user(&affinity, user_out, sizeof(affinity)) == 0);
    assert(affinity == 2);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sys_sched_getaffinity_success,
                selftest_sys_sched_getaffinity_success);

/* Verify SYS_THREAD_GETSCHEDPARAM / SETSCHEDPARAM and SYS_SCHED_
 * GETSCHEDULER / SETSCHEDULER on the calling thread. The mock task's
 * td_base_prio is set explicitly so the privilege check (cannot raise
 * above own base) does not reject the test value.
 */
static i32 selftest_thread_schedparam(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));
    td->td_base_prio = (u8) (CONFIG_SCHED_NPRIO - 1);
    /* The setschedparam path calls pi_mutex_refresh_prio which walks
     * td->pi_held_mutexes; the mock task is zero-initialized, so
     * initialize the list head to an empty (self-referential) state
     * before the syscall runs.
     */
    list_init(&td->pi_held_mutexes);

    struct trap_frame tf = {0};

    /* Self getschedparam returns current base priority. */
    tf.a7 = SYS_THREAD_GETSCHEDPARAM;
    tf.a0 = 0;
    assert(syscall_dispatch(&tf, td) == (i64) td->td_base_prio);

    /* Self setschedparam to a lower priority (allowed). */
    tf.a7 = SYS_THREAD_SETSCHEDPARAM;
    tf.a0 = 0;
    tf.a1 = SCHED_PRIO_IDLE;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(td->td_base_prio == SCHED_PRIO_IDLE);

    /* Bogus priority -> EINVAL. */
    tf.a1 = CONFIG_SCHED_NPRIO + 5;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Unknown thread handle -> ESRCH. */
    tf.a7 = SYS_THREAD_GETSCHEDPARAM;
    tf.a0 = (u64) -1;
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);

    /* sched_setscheduler / sched_getscheduler return SCHED_FIFO for
     * the current process; SCHED_OTHER and SCHED_RR are accepted as
     * input but coerced to the single supported policy.
     */
    tf.a7 = SYS_SCHED_GETSCHEDULER;
    tf.a0 = 0;
    assert(syscall_dispatch(&tf, td) == (i64) SCHED_FIFO);

    tf.a7 = SYS_SCHED_SETSCHEDULER;
    tf.a0 = 0;
    tf.a1 = SCHED_OTHER;
    tf.a2 = SCHED_PRIO_IDLE;
    assert(syscall_dispatch(&tf, td) == (i64) SCHED_FIFO);

    /* Bogus policy -> EINVAL. */
    tf.a1 = 99;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(thread_schedparam, selftest_thread_schedparam);

/* Verify SYS_THREAD_DETACH state transitions on a mock joinable
 * thread. Cannot truly run a second thread inside a selftest task
 * (we have no scheduler context for it here), but the lifecycle
 * helper paths can be exercised through state observations.
 */
static i32 selftest_thread_detach_states(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    /* Allocate a second mock task to act as the detach target.  Mark
     * it JOINABLE and attach via the reservation path.  The test
     * mutates state directly because no real scheduler context is
     * present for the secondary thread.
     */
    struct sched_task *target = alloc_mock_task();
    assert(target);
    target->td_join_state = TD_JOIN_JOINABLE;
    init_waitqueue_head(&target->td_join_wq);
    assert(attach_mock_thread(p, target));

    /* Detach the JOINABLE target -> succeeds, state becomes DETACHED. */
    struct trap_frame tf = {0};
    tf.a7 = SYS_THREAD_DETACH;
    tf.a0 = (u64) syscall_test_thread_token(p, target);
    assert(syscall_dispatch(&tf, td) == 0);
    assert(target->td_join_state == TD_JOIN_DETACHED);

    /* Second detach on a DETACHED thread -> EINVAL. */
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Join on a DETACHED thread -> EINVAL. */
    tf.a7 = SYS_THREAD_JOIN;
    tf.a0 = (u64) syscall_test_thread_token(p, target);
    tf.a1 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Self-join -> EDEADLK. */
    tf.a0 = (u64) syscall_test_thread_token(p, td);
    assert(syscall_dispatch(&tf, td) == -(i64) EDEADLK);

    /* Unknown thread handle -> ESRCH. */
    tf.a0 = (u64) -1;
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);

    /* Cleanup: detach the target before freeing the proc. */
    u64 flags = proc_table_lock_irqsave();
    proc_detach_task(p, target);
    proc_table_unlock_irqrestore(flags);
    free_mock_task(target);
    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(thread_detach_states, selftest_thread_detach_states);

static i32 selftest_thread_join_efault_preserves_exited_target(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct sched_task *target = alloc_mock_task();
    assert(target);
    target->proc = p;
    target->td_join_state = TD_JOIN_EXITED;
    target->td_exit_code = 42;
    init_waitqueue_head(&target->td_join_wq);
    assert(attach_mock_thread(p, target));

    struct trap_frame tf = {0};
    tf.a7 = SYS_THREAD_JOIN;
    tf.a0 = (u64) syscall_test_thread_token(p, target);
    tf.a1 = USER_CODE_BASE - sizeof(i32);
    assert(syscall_dispatch(&tf, td) == -(i64) EFAULT);
    assert(target->td_join_state == TD_JOIN_EXITED);
    assert(cap_slot_read(p, target->td_cap_slot).valid);

    const vaddr_t va = USER_DATA_BASE + (136UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);
    tf.a1 = (u64) va;
    assert(syscall_dispatch(&tf, td) == 0);
    i32 exit_code = 0;
    assert(copy_from_user(&exit_code, va, sizeof(exit_code)) == 0);
    assert(exit_code == 42);
    assert(!cap_slot_read(p, target->td_cap_slot).valid);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(thread_join_efault_preserves_exited_target,
                selftest_thread_join_efault_preserves_exited_target);

static i32 selftest_thread_handle_stale_rejected_after_reuse(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct sched_task *old_target = alloc_mock_task();
    assert(old_target);
    old_target->proc = p;
    old_target->td_join_state = TD_JOIN_JOINABLE;
    init_waitqueue_head(&old_target->td_join_wq);
    assert(attach_mock_thread(p, old_target));
    u64 stale_token = (u64) syscall_test_thread_token(p, old_target);

    u64 flags = proc_table_lock_irqsave();
    proc_detach_task(p, old_target);
    proc_table_unlock_irqrestore(flags);
    free_mock_task(old_target);

    struct sched_task *new_target = alloc_mock_task();
    assert(new_target);
    new_target->proc = p;
    new_target->td_join_state = TD_JOIN_JOINABLE;
    init_waitqueue_head(&new_target->td_join_wq);
    assert(attach_mock_thread(p, new_target));
    u64 fresh_token = (u64) syscall_test_thread_token(p, new_target);
    assert(fresh_token != stale_token);

    struct trap_frame tf = {0};
    tf.a7 = SYS_PTHREAD_KILL;
    tf.a0 = stale_token;
    tf.a1 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);

    tf.a0 = fresh_token;
    assert(syscall_dispatch(&tf, td) == 0);

    flags = proc_table_lock_irqsave();
    proc_detach_task(p, new_target);
    proc_table_unlock_irqrestore(flags);
    free_mock_task(new_target);
    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(thread_handle_stale_rejected_after_reuse,
                selftest_thread_handle_stale_rejected_after_reuse);

/* Verify clock_gettime on the per-thread and per-process CPU-time
 * clocks returns a valid timespec.  Mock task cpu_time_us is zero by
 * default; the values are still validated for shape (no fault, no
 * overflow into tv_nsec).
 */
static i32 selftest_clock_cputime(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (133UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_CLOCK_GETTIME;

    td->cpu_time_us = 1234567ULL;

    tf.a0 = CLOCK_THREAD_CPUTIME_ID;
    tf.a1 = (u64) va;
    assert(syscall_dispatch(&tf, td) == 0);
    struct timespec out;
    assert(copy_from_user(&out, va, sizeof(out)) == 0);
    assert(out.tv_sec == 1);
    assert(out.tv_nsec == 234567000);

    tf.a0 = CLOCK_PROCESS_CPUTIME_ID;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(copy_from_user(&out, va, sizeof(out)) == 0);
    /* Single-thread proc, so process CPU time equals thread CPU time. */
    assert(out.tv_sec == 1);
    assert(out.tv_nsec == 234567000);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(clock_cputime, selftest_clock_cputime);

/* pthread_kill: thread-directed signal lands on td_sig.pending of
 * the target, not on the per-proc proc_pending mask.
 */
static i32 selftest_pthread_kill(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};

    /* Self-target: signo lands on td->td_sig.pending. */
    tf.a7 = SYS_PTHREAD_KILL;
    tf.a0 = (u64) syscall_test_thread_token(p, td);
    tf.a1 = SIGUSR1;
    assert(syscall_dispatch(&tf, td) == 0);
    assert((td->td_sig.pending & sig_bit(SIGUSR1)) != 0);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) == 0);

    /* Existence check (signo == 0) returns 0 without writing. */
    td->td_sig.pending = 0;
    tf.a1 = 0;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(td->td_sig.pending == 0);

    /* SIGKILL on a single thread is rejected (it must be process-wide). */
    tf.a1 = SIGKILL;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Unknown thread handle -> ESRCH. */
    tf.a0 = (u64) -1;
    tf.a1 = SIGUSR1;
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pthread_kill, selftest_pthread_kill);

static i32 selftest_pthread_kill_exited_thread_esrch(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct sched_task *target = alloc_mock_task();
    assert(target);
    target->proc = p;
    target->td_join_state = TD_JOIN_EXITED;
    init_waitqueue_head(&target->td_join_wq);
    assert(attach_mock_thread(p, target));

    struct trap_frame tf = {0};
    tf.a7 = SYS_PTHREAD_KILL;
    tf.a0 = (u64) syscall_test_thread_token(p, target);
    tf.a1 = SIGUSR1;
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);
    assert(target->td_sig.pending == 0);

    u64 flags = proc_table_lock_irqsave();
    proc_detach_task(p, target);
    proc_table_unlock_irqrestore(flags);
    free_mock_task(target);
    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(pthread_kill_exited_thread_esrch,
                selftest_pthread_kill_exited_thread_esrch);

/* pthread_setcancelstate: ENABLE / DISABLE flip td_cancel_disabled
 * and report the prior state.
 */
static i32 selftest_thread_cancel_state(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (134UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_THREAD_SETCANCELSTATE;
    tf.a0 = PTHREAD_CANCEL_DISABLE;
    tf.a1 = (u64) va;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(td->td_cancel_disabled == true);
    i32 old;
    assert(copy_from_user(&old, va, sizeof(old)) == 0);
    assert(old == PTHREAD_CANCEL_ENABLE);

    tf.a0 = PTHREAD_CANCEL_ENABLE;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(td->td_cancel_disabled == false);
    assert(copy_from_user(&old, va, sizeof(old)) == 0);
    assert(old == PTHREAD_CANCEL_DISABLE);

    /* Bogus state -> EINVAL. */
    tf.a0 = 99;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* SYS_THREAD_CANCEL on unknown thread handle -> ESRCH. */
    tf.a7 = SYS_THREAD_CANCEL;
    tf.a0 = (u64) -1;
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);

    /* SYS_THREAD_CANCEL on self handle sets td_cancel_pending. */
    tf.a0 = (u64) syscall_test_thread_token(p, td);
    assert(syscall_dispatch(&tf, td) == 0);
    assert(td->td_cancel_pending == true);

    /* testcancel with cancellation disabled returns 0 without
     * exiting the thread.
     */
    td->td_cancel_disabled = true;
    tf.a7 = SYS_THREAD_TESTCANCEL;
    assert(syscall_dispatch(&tf, td) == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(thread_cancel_state, selftest_thread_cancel_state);

static i32 selftest_thread_cancel_exited_thread_esrch(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct sched_task *target = alloc_mock_task();
    assert(target);
    target->proc = p;
    target->td_join_state = TD_JOIN_EXITED;
    init_waitqueue_head(&target->td_join_wq);
    assert(attach_mock_thread(p, target));

    struct trap_frame tf = {0};
    tf.a7 = SYS_THREAD_CANCEL;
    tf.a0 = (u64) syscall_test_thread_token(p, target);
    assert(syscall_dispatch(&tf, td) == -(i64) ESRCH);
    assert(target->td_cancel_pending == false);

    u64 flags = proc_table_lock_irqsave();
    proc_detach_task(p, target);
    proc_table_unlock_irqrestore(flags);
    free_mock_task(target);
    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(thread_cancel_exited_thread_esrch,
                selftest_thread_cancel_exited_thread_esrch);

/* sigtimedwait: zero set -> EINVAL; immediate timeout if no signals
 * pending; immediate dequeue if signal already pending.
 */
static i32 selftest_sigtimedwait(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (135UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGTIMEDWAIT;

    /* Empty set -> EINVAL. */
    u32 set = 0;
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = (u64) va;
    tf.a1 = 0;
    tf.a2 = 0;
    tf.a3 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EINVAL);

    /* Pre-pend a signal in the per-thread mask, then sigtimedwait
     * should dequeue it immediately and return its number.
     */
    td->td_sig.pending = sig_bit(SIGUSR1) | sig_bit(SIGUSR2);
    set = sig_bit(SIGUSR2);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a0 = (u64) va;
    tf.a1 = (u64) (va + sizeof(u32));
    tf.a2 = 0;
    tf.a3 = 0;
    i64 ret = syscall_dispatch(&tf, td);
    assert(ret == SIGUSR2);
    assert((td->td_sig.pending & sig_bit(SIGUSR2)) == 0);
    assert((td->td_sig.pending & sig_bit(SIGUSR1)) != 0);
    i32 sout;
    assert(copy_from_user(&sout, va + sizeof(u32), sizeof(sout)) == 0);
    assert(sout == SIGUSR2);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigtimedwait, selftest_sigtimedwait);

static i32 selftest_sigqueue_payload(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (136UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR1;
    tf.a2 = 0x1122334455667788ULL;
    assert(syscall_dispatch(&tf, td) == 0);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) != 0);

    u32 set = sig_bit(SIGUSR1);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);

    tf.a7 = SYS_SIGTIMEDWAIT;
    tf.a0 = (u64) va;
    tf.a1 = (u64) (va + sizeof(u32));
    tf.a2 = 0;
    tf.a3 = (u64) (va + sizeof(u32) + sizeof(i32));
    assert(syscall_dispatch(&tf, td) == SIGUSR1);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) == 0);
    assert(p->sig_state.queued[SIGUSR1].count == 0);

    i32 signo_out;
    u64 value_out;
    assert(copy_from_user(&signo_out, va + sizeof(u32), sizeof(signo_out)) ==
           0);
    assert(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                          sizeof(value_out)) == 0);
    assert(signo_out == SIGUSR1);
    assert(value_out == 0x1122334455667788ULL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigqueue_payload, selftest_sigqueue_payload);

static i32 selftest_sigqueue_full(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR2;

    for (u64 i = 0; i < SIGQUEUE_MAX_PER_SIGNO; i++) {
        tf.a2 = i + 1;
        assert(syscall_dispatch(&tf, td) == 0);
    }

    tf.a2 = 99;
    assert(syscall_dispatch(&tf, td) == -(i64) EAGAIN);
    assert(p->sig_state.queued[SIGUSR2].count == SIGQUEUE_MAX_PER_SIGNO);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigqueue_full, selftest_sigqueue_full);

/* FIFO order across multiple queued sigqueue payloads: dequeues must
 * return values in the order they were posted.
 */
static i32 selftest_sigqueue_fifo(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (137UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR1;
    for (u64 i = 0; i < SIGQUEUE_MAX_PER_SIGNO; i++) {
        tf.a2 = 0x100 + i;
        assert(syscall_dispatch(&tf, td) == 0);
    }
    assert(p->sig_state.queued[SIGUSR1].count == SIGQUEUE_MAX_PER_SIGNO);

    u32 set = sig_bit(SIGUSR1);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);

    for (u64 i = 0; i < SIGQUEUE_MAX_PER_SIGNO; i++) {
        tf.a7 = SYS_SIGTIMEDWAIT;
        tf.a0 = (u64) va;
        tf.a1 = (u64) (va + sizeof(u32));
        tf.a2 = 0;
        tf.a3 = (u64) (va + sizeof(u32) + sizeof(i32));
        assert(syscall_dispatch(&tf, td) == SIGUSR1);
        u64 value_out;
        assert(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                              sizeof(value_out)) == 0);
        assert(value_out == 0x100 + i);
    }
    assert(p->sig_state.queued[SIGUSR1].count == 0);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) == 0);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR1)) == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigqueue_fifo, selftest_sigqueue_fifo);

/* kill() followed by sigqueue() on the same signo: consuming the queued
 * payload must not silently clear the plain pending instance. The receiver
 * dequeues the sigqueue payload first (FIFO), then the plain kill instance
 * with no payload.
 */
static i32 selftest_sigqueue_then_kill_coexist(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (138UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    /* First: plain kill(). */
    tf.a7 = SYS_KILL;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR2;
    assert(syscall_dispatch(&tf, td) == 0);
    /* Then: sigqueue() with payload. */
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR2;
    tf.a2 = 0xdeadbeefULL;
    assert(syscall_dispatch(&tf, td) == 0);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR2)) != 0);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR2)) != 0);
    assert(p->sig_state.queued[SIGUSR2].count == 1);

    /* First dequeue: sigqueue payload. */
    u32 set = sig_bit(SIGUSR2);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    u64 sentinel = 0xa5a5a5a5a5a5a5a5ULL;
    assert(copy_to_user(va + sizeof(u32) + sizeof(i32), &sentinel,
                        sizeof(sentinel)) == 0);
    tf.a7 = SYS_SIGTIMEDWAIT;
    tf.a0 = (u64) va;
    tf.a1 = (u64) (va + sizeof(u32));
    tf.a2 = 0;
    tf.a3 = (u64) (va + sizeof(u32) + sizeof(i32));
    assert(syscall_dispatch(&tf, td) == SIGUSR2);
    u64 value_out;
    assert(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                          sizeof(value_out)) == 0);
    assert(value_out == 0xdeadbeefULL);
    /* Plain instance must still be pending after consuming the queued one. */
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR2)) != 0);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR2)) != 0);
    assert(p->sig_state.queued[SIGUSR2].count == 0);

    /* Second dequeue: plain kill instance, payload untouched. */
    assert(copy_to_user(va + sizeof(u32) + sizeof(i32), &sentinel,
                        sizeof(sentinel)) == 0);
    assert(syscall_dispatch(&tf, td) == SIGUSR2);
    assert(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                          sizeof(value_out)) == 0);
    assert(value_out == sentinel);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR2)) == 0);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR2)) == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigqueue_then_kill_coexist,
                selftest_sigqueue_then_kill_coexist);

/* sigqueue() followed by kill() on the same signo: same invariant in
 * reverse arrival order. The queued payload still comes out first.
 */
static i32 selftest_kill_then_sigqueue_coexist(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (139UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR1;
    tf.a2 = 0xcafebabeULL;
    assert(syscall_dispatch(&tf, td) == 0);
    tf.a7 = SYS_KILL;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR1;
    assert(syscall_dispatch(&tf, td) == 0);
    assert(p->sig_state.queued[SIGUSR1].count == 1);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR1)) != 0);

    u32 set = sig_bit(SIGUSR1);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a7 = SYS_SIGTIMEDWAIT;
    tf.a0 = (u64) va;
    tf.a1 = (u64) (va + sizeof(u32));
    tf.a2 = 0;
    tf.a3 = (u64) (va + sizeof(u32) + sizeof(i32));
    assert(syscall_dispatch(&tf, td) == SIGUSR1);
    u64 value_out;
    assert(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                          sizeof(value_out)) == 0);
    assert(value_out == 0xcafebabeULL);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR1)) != 0);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) != 0);

    /* Drain the plain instance. */
    assert(syscall_dispatch(&tf, td) == SIGUSR1);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) == 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(kill_then_sigqueue_coexist,
                selftest_kill_then_sigqueue_coexist);

/* Realistic concurrent-producer rollback: queue is full at the producer cap,
 * a consumer dequeues the head, a producer immediately refills the vacated
 * slot, then the consumer's copy_to_user faults and triggers rollback. The
 * reserved internal slot must let the rollback succeed losslessly, restoring
 * FIFO order (the originally-popped value comes out next).
 */
static i32 selftest_sigqueue_restore_lossless(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    u64 sflags = proc_sig_lock_irqsave(p);
    /* Producer fills the queue to MAX. */
    for (u64 i = 0; i < SIGQUEUE_MAX_PER_SIGNO; i++) {
        p->sig_state.queued[SIGUSR1].values[i] = 0xb000 + i;
    }
    p->sig_state.queued[SIGUSR1].head = 0;
    p->sig_state.queued[SIGUSR1].tail = SIGQUEUE_MAX_PER_SIGNO;
    p->sig_state.queued[SIGUSR1].count = SIGQUEUE_MAX_PER_SIGNO;
    p->sig_state.proc_pending |= sig_bit(SIGUSR1);

    /* Consumer dequeues into a local. */
    u64 popped;
    bool had_value;
    assert(signal_claim_proc_pending_locked(p, SIGUSR1, &popped, &had_value));
    assert(had_value == true);
    assert(popped == 0xb000);
    assert(p->sig_state.queued[SIGUSR1].count == SIGQUEUE_MAX_PER_SIGNO - 1);
    proc_sig_unlock_irqrestore(p, sflags);

    /* Producer refills the slot we vacated. */
    i32 rc = signal_queue_send(p, SIGUSR1, 0xb004);
    assert(rc == 0);
    assert(p->sig_state.queued[SIGUSR1].count == SIGQUEUE_MAX_PER_SIGNO);

    /* Consumer faults during copy_to_user and rolls back. The reserved
     * internal slot makes the push lossless.
     */
    sflags = proc_sig_lock_irqsave(p);
    bool dropped = signal_restore_proc_pending_locked(p, SIGUSR1, popped, true);
    assert(dropped == false);
    assert(p->sig_state.queued[SIGUSR1].count == SIGQUEUE_MAX_PER_SIGNO + 1);

    /* FIFO must place the restored value back at the head. */
    u64 v;
    bool h;
    assert(signal_claim_proc_pending_locked(p, SIGUSR1, &v, &h));
    assert(h == true && v == 0xb000);
    proc_sig_unlock_irqrestore(p, sflags);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigqueue_restore_lossless, selftest_sigqueue_restore_lossless);

/* Defense-in-depth: if the ring is somehow filled past the user-visible cap
 * (pathological multi-consumer race), the rollback helper must still avoid
 * corrupting q->count and must surface a plain pending instance so the
 * signal stays observable. The payload is lost in this branch by design.
 */
static i32 selftest_sigqueue_restore_overflow(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    u64 sflags = proc_sig_lock_irqsave(p);
    for (u64 i = 0; i < SIGQUEUE_RING_CAP; i++) {
        p->sig_state.queued[SIGUSR1].values[i] = 0xa000 + i;
    }
    p->sig_state.queued[SIGUSR1].head = 0;
    p->sig_state.queued[SIGUSR1].tail = 0;
    p->sig_state.queued[SIGUSR1].count = SIGQUEUE_RING_CAP;
    p->sig_state.proc_pending |= sig_bit(SIGUSR1);

    bool dropped = signal_restore_proc_pending_locked(p, SIGUSR1, 0xdead, true);
    proc_sig_unlock_irqrestore(p, sflags);

    assert(dropped == true);
    assert(p->sig_state.queued[SIGUSR1].count == SIGQUEUE_RING_CAP);
    assert((p->sig_state.proc_pending_plain & sig_bit(SIGUSR1)) != 0);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) != 0);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigqueue_restore_overflow, selftest_sigqueue_restore_overflow);

/* sigtimedwait pre-validation rejects an unwritable signo_out without
 * consuming the queued payload, so a retry can observe it.
 */
static i32 selftest_sigtimedwait_efault_rollback(void)
{
    struct proc *p;
    struct sched_task *td;
    assert(alloc_proc_and_task(&p, &td));

    const vaddr_t va = USER_DATA_BASE + (140UL * PAGE_SIZE);
    assert(proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error ==
           false);

    struct trap_frame tf = {0};
    tf.a7 = SYS_SIGQUEUE;
    tf.a0 = p->pid;
    tf.a1 = SIGUSR1;
    tf.a2 = 0x42ULL;
    assert(syscall_dispatch(&tf, td) == 0);

    /* Pass an unmapped pointer for signo_out. Pre-validation in
     * sys_sigtimedwait_h catches this before the bit is consumed, so the
     * queue must still hold the payload.
     */
    u32 set = sig_bit(SIGUSR1);
    assert(copy_to_user(va, &set, sizeof(set)) == 0);
    tf.a7 = SYS_SIGTIMEDWAIT;
    tf.a0 = (u64) va;
    tf.a1 = (u64) 0xdeadc0deUL;
    tf.a2 = 0;
    tf.a3 = 0;
    assert(syscall_dispatch(&tf, td) == -(i64) EFAULT);
    assert(p->sig_state.queued[SIGUSR1].count == 1);
    assert((p->sig_state.proc_pending & sig_bit(SIGUSR1)) != 0);
    /* Retry with a valid pointer must observe the still-queued payload. */
    tf.a1 = (u64) (va + sizeof(u32));
    tf.a3 = (u64) (va + sizeof(u32) + sizeof(i32));
    assert(syscall_dispatch(&tf, td) == SIGUSR1);
    u64 value_out;
    assert(copy_from_user(&value_out, va + sizeof(u32) + sizeof(i32),
                          sizeof(value_out)) == 0);
    assert(value_out == 0x42ULL);

    free_proc_and_task(p, td);
    return 0;
}
DEFINE_SELFTEST(sigtimedwait_efault_rollback,
                selftest_sigtimedwait_efault_rollback);

/* ABI stability check: SYS_SIGQUEUE is appended at the end of the table; the
 * pre-existing trailing entries must keep their numbers.
 */
static i32 selftest_sigqueue_abi_numbering(void)
{
    static_assert(SYS_THREAD_CANCEL == 93, "SYS_THREAD_CANCEL must stay at 93");
    static_assert(SYS_THREAD_SETCANCELSTATE == 94,
                  "SYS_THREAD_SETCANCELSTATE must stay at 94");
    static_assert(SYS_THREAD_TESTCANCEL == 95,
                  "SYS_THREAD_TESTCANCEL must stay at 95");
    static_assert(SYS_CAP_DROP == 96, "SYS_CAP_DROP must stay at 96");
    static_assert(SYS_CAP_TRANSFER == 97, "SYS_CAP_TRANSFER must stay at 97");
    static_assert(SYS_CAP_REVOKE_DELEGATE == 98,
                  "SYS_CAP_REVOKE_DELEGATE must stay at 98");
    static_assert(SYS_CAP_GET_TOKEN == 99, "SYS_CAP_GET_TOKEN must stay at 99");
    static_assert(SYS_SIGQUEUE == 100, "SYS_SIGQUEUE must be appended at 100");
    static_assert(SYS_NR == 101, "SYS_NR must stay at 101");
    return 0;
}
DEFINE_SELFTEST(sigqueue_abi_numbering, selftest_sigqueue_abi_numbering);
