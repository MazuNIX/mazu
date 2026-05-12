/* SPDX-License-Identifier: MIT */
/* Shared proc/task helpers for syscall-facing selftests.
 *
 * These helpers intentionally live in tests/ because they allocate mock
 * sched_task instances and wire them into the proc/cap tables without
 * going through the full user-thread creation path. That is appropriate
 * for syscall ABI validation where we need a stable proc + current-task
 * context but not a live scheduled peer thread.
 */

#ifndef TESTS_PROC_HELPERS_H
#define TESTS_PROC_HELPERS_H

#include <mazu/cap.h>
#include <mazu/kvalloc.h>
#include <mazu/proc.h>

static inline struct proc *alloc_running_proc(void)
{
    struct proc *p = proc_alloc();

    if (p)
        proc_set_state(p, PROC_STATE_RUNNING);
    return p;
}

static inline struct sched_task *alloc_mock_task(void)
{
    struct option_byte_array td_mem =
        kvalloc_alloc(sizeof(struct sched_task), alignof(struct sched_task));

    if (td_mem.is_none)
        return NULL;
    struct sched_task *td = byte_array_ptr(option_byte_array_checked(td_mem));

    memset(td, 0, sizeof(*td));
    td->td_cap_slot = -1;
    return td;
}

static inline void free_mock_task(struct sched_task *td)
{
    kvalloc_free(byte_array_new((byte *) td, sizeof(*td)));
}

static inline i32 syscall_test_thread_cap_slot(u8 task_slot)
{
    return CAP_SPACE_SLOTS - PROC_THREAD_MAX + (i32) task_slot;
}

static inline i64 syscall_test_thread_token(struct proc *p,
                                            struct sched_task *td)
{
    assert(p);
    assert(td);
    assert(td->td_cap_slot >= 0);
    return cap_get_token(p, td->td_cap_slot, CAP_TYPE_THREAD);
}

static inline bool alloc_proc_and_task(struct proc **out_p,
                                       struct sched_task **out_td)
{
    struct proc *p = alloc_running_proc();

    if (!p)
        return false;
    struct sched_task *td = alloc_mock_task();
    if (!td) {
        proc_set_state(p, PROC_STATE_ZOMBIE);
        proc_free(p);
        return false;
    }
    td->proc = p;
    {
        u64 pflags = proc_table_lock_irqsave();
        bool ok = proc_attach_task(p, td);
        proc_table_unlock_irqrestore(pflags);
        if (!ok) {
            free_mock_task(td);
            proc_set_state(p, PROC_STATE_ZOMBIE);
            proc_free(p);
            return false;
        }
    }
    u8 thread_slot = proc_task_slot(p, td);
    i32 thread_handle = cap_open_handle(
        p, thread_slot, CAP_TYPE_THREAD, CAP_RIGHT_READ | CAP_RIGHT_WRITE,
        syscall_test_thread_cap_slot(thread_slot), true);
    if (thread_handle < 0) {
        u64 pflags = proc_table_lock_irqsave();
        (void) proc_reap_exited_thread_locked(p, td);
        proc_table_unlock_irqrestore(pflags);
        free_mock_task(td);
        proc_set_state(p, PROC_STATE_ZOMBIE);
        proc_free(p);
        return false;
    }
    td->td_cap_slot = (i16) thread_handle;
    *out_p = p;
    *out_td = td;
    return true;
}

static inline void free_proc_and_task(struct proc *p, struct sched_task *td)
{
    proc_set_state(p, PROC_STATE_ZOMBIE);
    proc_free(p);
    free_mock_task(td);
}

static inline bool attach_mock_thread(struct proc *p, struct sched_task *target)
{
    u8 slot = PROC_THREAD_MAX;
    u64 flags = proc_table_lock_irqsave();
    bool ok = proc_reserve_thread_slot(p, &slot);
    proc_table_unlock_irqrestore(flags);
    if (!ok)
        return false;
    flags = proc_table_lock_irqsave();
    ok = proc_attach_task_slot(p, target, slot);
    proc_table_unlock_irqrestore(flags);
    if (!ok)
        return false;
    i32 thread_handle = cap_open_handle(
        p, slot, CAP_TYPE_THREAD, CAP_RIGHT_READ | CAP_RIGHT_WRITE,
        syscall_test_thread_cap_slot(slot), true);
    if (thread_handle < 0) {
        flags = proc_table_lock_irqsave();
        (void) proc_reap_exited_thread_locked(p, target);
        proc_table_unlock_irqrestore(flags);
        return false;
    }
    target->td_cap_slot = (i16) thread_handle;
    return true;
}

#endif /* TESTS_PROC_HELPERS_H */
