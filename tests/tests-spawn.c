/* SPDX-License-Identifier: MIT */
#include <mazu/cap.h>
#include <mazu/selftest.h>
#include <mazu/spawn.h>
#include <mazu/vfs.h>

/* Helper: check if VFS has /hello.txt available (may not in some configs). */
static bool spawn_test_vfs_available(void)
{
    struct result_vfs_file f = vfs_open(STR("/hello.txt"));
    if (f.is_error)
        return false;
    struct vfs_file vf = result_vfs_file_checked(f);
    vfs_close(&vf);
    return true;
}

/* Test spawn_apply_file_actions: SPAWN_FA_CLOSE removes an FD. */
static i32 selftest_spawn_fa_close(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    /* FDs 0/1/2 are open by default. Close FD 1 (stdout). */
    struct spawn_file_action fa = {
        .type = SPAWN_FA_CLOSE,
        .fd = PROC_FD_STDOUT,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == 0);
    assert(!cap_fd_is_valid(p, PROC_FD_STDOUT));

    /* FDs 0 and 2 should still be open. */
    assert(cap_fd_is_valid(p, PROC_FD_STDIN));
    assert(cap_fd_is_valid(p, PROC_FD_STDERR));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_close, selftest_spawn_fa_close);

/* Test spawn_apply_file_actions: SPAWN_FA_DUP2 duplicates an FD. */
static i32 selftest_spawn_fa_dup2(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    /* Dup FD 0 (stdin) to FD 5. */
    struct spawn_file_action fa = {
        .type = SPAWN_FA_DUP2,
        .fd = PROC_FD_STDIN,
        .newfd = 5,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == 0);
    assert(cap_fd_is_valid(p, 5));
    assert(cap_fd_is_valid(p, PROC_FD_STDIN));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_dup2, selftest_spawn_fa_dup2);

/* Test spawn_apply_file_actions: SPAWN_FA_OPEN opens a ramfs file. */
static i32 selftest_spawn_fa_open(void)
{
    if (!spawn_test_vfs_available())
        return 0; /* skip gracefully */

    struct proc *p = proc_alloc();
    assert(p);

    char path[] = "/hello.txt";
    struct spawn_file_action fa = {
        .type = SPAWN_FA_OPEN,
        .fd = 5,
        .pathlen = 10,
        .path = (u64) (uptr) path,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == 0);
    assert(cap_fd_is_valid(p, 5));
    assert(cap_fd_is_seekable(p, 5));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_open, selftest_spawn_fa_open);

/* Test SPAWN_FA_OPEN replacing an existing open FD. */
static i32 selftest_spawn_fa_open_replace(void)
{
    if (!spawn_test_vfs_available())
        return 0;

    struct proc *p = proc_alloc();
    assert(p);

    char path[] = "/hello.txt";
    struct spawn_file_action fa = {
        .type = SPAWN_FA_OPEN,
        .fd = PROC_FD_STDIN,
        .pathlen = 10,
        .path = (u64) (uptr) path,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == 0);
    assert(cap_fd_is_valid(p, PROC_FD_STDIN));
    assert(cap_fd_is_seekable(p, PROC_FD_STDIN));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_open_replace, selftest_spawn_fa_open_replace);

/* Test multiple file actions executed sequentially. */
static i32 selftest_spawn_fa_multi(void)
{
    if (!spawn_test_vfs_available())
        return 0;

    struct proc *p = proc_alloc();
    assert(p);

    char path[] = "/hello.txt";
    struct spawn_file_action fas[3] = {
        /* 1. Close stderr */
        {.type = SPAWN_FA_CLOSE, .fd = PROC_FD_STDERR},
        /* 2. Open a file at FD 3 */
        {.type = SPAWN_FA_OPEN,
         .fd = 3,
         .pathlen = 10,
         .path = (u64) (uptr) path},
        /* 3. Dup FD 3 to FD 4 */
        {.type = SPAWN_FA_DUP2, .fd = 3, .newfd = 4},
    };

    i32 rc = spawn_apply_file_actions(p, fas, 3);
    assert(rc == 0);
    assert(!cap_fd_is_valid(p, PROC_FD_STDERR));
    assert(cap_fd_is_valid(p, 3));
    assert(cap_fd_is_valid(p, 4));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_multi, selftest_spawn_fa_multi);

/* Test spawn_apply_file_actions: invalid action type returns EINVAL. */
static i32 selftest_spawn_fa_invalid_type(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    struct spawn_file_action fa = {
        .type = 99,
        .fd = 0,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == -(i32) EINVAL);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_invalid_type, selftest_spawn_fa_invalid_type);

/* Test spawn_apply_file_actions: bad FD range returns EBADF. */
static i32 selftest_spawn_fa_bad_fd(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    struct spawn_file_action fa = {
        .type = SPAWN_FA_CLOSE,
        .fd = PROC_FD_MAX + 1,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == -(i32) EBADF);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_bad_fd, selftest_spawn_fa_bad_fd);

/* Test spawn_apply_file_actions: too many actions returns EINVAL. */
static i32 selftest_spawn_fa_too_many(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    struct spawn_file_action fas[1]; /* dummy, count matters */
    i32 rc = spawn_apply_file_actions(p, fas, SPAWN_FA_MAX + 1);
    assert(rc == -(i32) EINVAL);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_too_many, selftest_spawn_fa_too_many);

/* Test spawn_apply_attr: set priority. */
static i32 selftest_spawn_attr_prio(void)
{
    u8 prio = SCHED_PRIO_NORMAL;
    struct spawn_attr attr = {
        .flags = SPAWN_ATTR_SETPRIO,
        .sched_priority = SCHED_PRIO_HIGH,
    };
    i32 rc = spawn_apply_attr(NULL, &attr, &prio);
    assert(rc == 0);
    assert(prio == SCHED_PRIO_HIGH);
    return 0;
}
DEFINE_SELFTEST(spawn_attr_prio, selftest_spawn_attr_prio);

/* Test spawn_apply_attr: invalid priority returns EINVAL. */
static i32 selftest_spawn_attr_bad_prio(void)
{
    u8 prio = SCHED_PRIO_NORMAL;
    struct spawn_attr attr = {
        .flags = SPAWN_ATTR_SETPRIO,
        .sched_priority = SCHED_PRIO_REALTIME + 1,
    };
    i32 rc = spawn_apply_attr(NULL, &attr, &prio);
    assert(rc == -(i32) EINVAL);
    return 0;
}
DEFINE_SELFTEST(spawn_attr_bad_prio, selftest_spawn_attr_bad_prio);

/* Test spawn_apply_attr: unknown flags return EINVAL. */
static i32 selftest_spawn_attr_unknown_flags(void)
{
    u8 prio = SCHED_PRIO_NORMAL;
    struct spawn_attr attr = {
        .flags = 0xFF,
    };
    i32 rc = spawn_apply_attr(NULL, &attr, &prio);
    assert(rc == -(i32) EINVAL);
    return 0;
}
DEFINE_SELFTEST(spawn_attr_unknown_flags, selftest_spawn_attr_unknown_flags);

/* Test spawn_apply_attr: no flags is a no-op. */
static i32 selftest_spawn_attr_noop(void)
{
    u8 prio = SCHED_PRIO_NORMAL;
    struct spawn_attr attr = {.flags = 0};
    i32 rc = spawn_apply_attr(NULL, &attr, &prio);
    assert(rc == 0);
    assert(prio == SCHED_PRIO_NORMAL);
    return 0;
}
DEFINE_SELFTEST(spawn_attr_noop, selftest_spawn_attr_noop);

/* File actions run in caller order. dup2(3,4) followed by close(3)
 * must leave fd 4 open while closing only the source slot.
 */
static i32 selftest_spawn_fa_dup2_then_close_order(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    struct spawn_file_action fas[2] = {
        {.type = SPAWN_FA_DUP2, .fd = PROC_FD_STDIN, .newfd = 4},
        {.type = SPAWN_FA_CLOSE, .fd = PROC_FD_STDIN},
    };

    i32 rc = spawn_apply_file_actions(p, fas, 2);
    assert(rc == 0);
    assert(cap_fd_is_valid(p, 4));
    assert(!cap_fd_is_valid(p, PROC_FD_STDIN));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_dup2_then_close_order,
                selftest_spawn_fa_dup2_then_close_order);

/* File actions must observe earlier child-side dup2 mutations. */
static i32 selftest_spawn_fa_dup2_chain_order(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    struct spawn_file_action fas[2] = {
        {.type = SPAWN_FA_DUP2, .fd = PROC_FD_STDIN, .newfd = 3},
        {.type = SPAWN_FA_DUP2, .fd = 3, .newfd = 4},
    };

    i32 rc = spawn_apply_file_actions(p, fas, 2);
    assert(rc == 0);
    assert(cap_fd_is_valid(p, 3));
    assert(cap_fd_is_valid(p, 4));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_dup2_chain_order, selftest_spawn_fa_dup2_chain_order);

/* Test zero file actions is a no-op. */
static i32 selftest_spawn_fa_zero(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i32 rc = spawn_apply_file_actions(p, NULL, 0);
    assert(rc == 0);

    /* All default FDs should still be open. */
    assert(cap_fd_is_valid(p, PROC_FD_STDIN));
    assert(cap_fd_is_valid(p, PROC_FD_STDOUT));
    assert(cap_fd_is_valid(p, PROC_FD_STDERR));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_zero, selftest_spawn_fa_zero);

static i32 selftest_spawn_fa_open_grants_inherit(void)
{
    if (!spawn_test_vfs_available())
        return 0;

    struct proc *p = proc_alloc();
    assert(p);

    char path[] = "/hello.txt";
    struct spawn_file_action fa = {
        .type = SPAWN_FA_OPEN,
        .fd = 5,
        .pathlen = 10,
        .path = (u64) (uptr) path,
    };
    i32 rc = spawn_apply_file_actions(p, &fa, 1);
    assert(rc == 0);
    assert(cap_fd_has_rights(p, 5, CAP_RIGHT_GRANT));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(spawn_fa_open_grants_inherit,
                selftest_spawn_fa_open_grants_inherit);
