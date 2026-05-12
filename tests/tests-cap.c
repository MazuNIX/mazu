/* SPDX-License-Identifier: MIT */

#include <kernel/ipc/mqueue.h>
#include <kernel/proc/pipe.h>
#include <kernel/sync/sync_handle.h>
#include <kernel/timer/posix_timer.h>
#include <mazu/cap.h>
#include <mazu/kvalloc.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/selftest.h>

static i32 selftest_cap_drop_invalidates_token(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i64 token = cap_get_token(p, PROC_FD_STDOUT, CAP_TYPE_FD);
    assert(token > 0);
    assert(cap_drop_token(p, (u64) token) == 0);
    assert(!cap_fd_is_valid(p, PROC_FD_STDOUT));
    assert(cap_drop_token(p, (u64) token) == -(i64) EBADF);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_drop_invalidates_token,
                selftest_cap_drop_invalidates_token);

static i32 selftest_cap_timer_token_drop(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i32 object_index = posix_timer_alloc(p);
    assert(object_index >= 0);
    i32 handle = cap_open_timer(p, (u16) object_index,
                                CAP_RIGHT_READ | CAP_RIGHT_WRITE, 3, true);
    assert(handle == 3);

    i64 token = cap_get_token(p, handle, CAP_TYPE_TIMER);
    assert(token > 0);
    assert(cap_drop_token(p, (u64) token) == 0);
    assert(!cap_slot_read(p, handle).valid);
    struct posix_timer *timer = posix_timer_ptr((u16) object_index);
    assert(timer);
    assert(!timer->in_use);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_timer_token_drop, selftest_cap_timer_token_drop);

static i32 selftest_cap_transfer_revokes_child_dups(void)
{
    struct proc *parent = proc_alloc();
    struct proc *child = proc_alloc();
    assert(parent);
    assert(child);

    struct pipe *pipe = pipe_alloc();
    assert(pipe);
    assert(cap_open_pipe(parent, pipe, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT,
                         3, true) == 3);

    i64 src_token = cap_get_token(parent, 3, CAP_TYPE_FD);
    assert(src_token > 0);
    i64 delegate =
        cap_transfer(parent, child->pid, (u64) src_token, CAP_RIGHT_READ);
    assert(delegate > 0);

    assert(cap_fd_is_valid(child, 3));
    i64 child_token = cap_get_token(child, 3, CAP_TYPE_FD);
    assert(child_token > 0);
    assert(cap_transfer(child, parent->pid, (u64) child_token,
                        CAP_RIGHT_READ) == -(i64) EACCES);

    assert(cap_dup_fd(child, 3, 4, true) == 4);
    assert(cap_fd_is_valid(child, 4));

    assert(cap_revoke_delegate(parent, (u64) delegate) == 0);
    assert(!cap_fd_is_valid(child, 3));
    assert(!cap_fd_is_valid(child, 4));

    proc_free(parent);
    proc_free(child);
    return 0;
}
DEFINE_SELFTEST(cap_transfer_revokes_child_dups,
                selftest_cap_transfer_revokes_child_dups);

static i32 selftest_cap_inherit_preserves_rights(void)
{
    struct proc *parent = proc_alloc();
    struct proc *child = proc_alloc();
    struct proc *grandchild = proc_alloc();
    assert(parent);
    assert(child);
    assert(grandchild);

    assert(cap_inherit_fd(parent, child, PROC_FD_STDOUT, 5) == 5);
    assert(cap_fd_is_valid(child, 5));
    assert(cap_fd_has_rights(child, 5, CAP_RIGHT_GRANT));
    assert(cap_fd_has_rights(child, 5, CAP_RIGHT_WRITE));

    assert(cap_inherit_fd(child, grandchild, 5, 6) == 6);
    assert(cap_fd_is_valid(grandchild, 6));
    assert(cap_fd_has_rights(grandchild, 6, CAP_RIGHT_GRANT));

    proc_free(parent);
    proc_free(child);
    proc_free(grandchild);
    return 0;
}
DEFINE_SELFTEST(cap_inherit_preserves_rights,
                selftest_cap_inherit_preserves_rights);

static i32 selftest_cap_revoke_preserves_unrelated_aliases(void)
{
    struct proc *parent = proc_alloc();
    struct proc *child = proc_alloc();
    assert(parent);
    assert(child);

    struct pipe *pipe = pipe_alloc();
    assert(pipe);
    assert(cap_open_pipe(parent, pipe, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT,
                         3, true) == 3);

    i64 src_token = cap_get_token(parent, 3, CAP_TYPE_FD);
    assert(src_token > 0);

    i64 delegate_a =
        cap_transfer(parent, child->pid, (u64) src_token, CAP_RIGHT_READ);
    assert(delegate_a > 0);
    assert(cap_fd_is_valid(child, 3));

    assert(cap_dup_fd(child, 3, 4, true) == 4);
    assert(cap_fd_is_valid(child, 4));

    i64 delegate_b =
        cap_transfer(parent, child->pid, (u64) src_token, CAP_RIGHT_READ);
    assert(delegate_b > 0);
    assert(cap_fd_is_valid(child, 5));

    assert(cap_revoke_delegate(parent, (u64) delegate_a) == 0);
    assert(!cap_fd_is_valid(child, 3));
    assert(!cap_fd_is_valid(child, 4));
    assert(cap_fd_is_valid(child, 5));

    proc_free(parent);
    proc_free(child);
    return 0;
}
DEFINE_SELFTEST(cap_revoke_preserves_unrelated_aliases,
                selftest_cap_revoke_preserves_unrelated_aliases);

static i32 selftest_cap_inherit_clones_non_grant_fd(void)
{
    struct proc *parent = proc_alloc();
    struct proc *child = proc_alloc();
    assert(parent);
    assert(child);

    struct pipe *pipe = pipe_alloc();
    assert(pipe);
    assert(cap_open_pipe(parent, pipe, true, CAP_RIGHT_READ, 3, true) == 3);
    assert(!cap_fd_has_rights(parent, 3, CAP_RIGHT_GRANT));

    assert(cap_inherit_fd(parent, child, 3, 3) == 3);
    assert(cap_fd_is_valid(child, 3));
    assert(cap_fd_has_rights(child, 3, CAP_RIGHT_READ));
    assert(!cap_fd_has_rights(child, 3, CAP_RIGHT_GRANT));

    proc_free(parent);
    proc_free(child);
    return 0;
}
DEFINE_SELFTEST(cap_inherit_clones_non_grant_fd,
                selftest_cap_inherit_clones_non_grant_fd);

static i32 selftest_cap_revoke_delegate_revokes_spawned_child(void)
{
    struct proc *donor = proc_alloc();
    struct proc *parent = proc_alloc();
    struct proc *child = proc_alloc();
    assert(donor);
    assert(parent);
    assert(child);

    struct pipe *pipe = pipe_alloc();
    assert(pipe);
    assert(cap_open_pipe(donor, pipe, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT, 3,
                         true) == 3);

    i64 src_token = cap_get_token(donor, 3, CAP_TYPE_FD);
    assert(src_token > 0);
    i64 delegate =
        cap_transfer(donor, parent->pid, (u64) src_token, CAP_RIGHT_READ);
    assert(delegate > 0);
    assert(cap_fd_is_valid(parent, 3));
    assert(!cap_fd_has_rights(parent, 3, CAP_RIGHT_GRANT));
    child->parent_pid = parent->pid;
    child->parent_generation = parent->generation;
    assert(cap_inherit_fd(parent, child, 3, 3) == 3);
    assert(cap_fd_is_valid(child, 3));

    assert(cap_revoke_delegate(donor, (u64) delegate) == 0);
    assert(!cap_fd_is_valid(parent, 3));
    assert(!cap_fd_is_valid(child, 3));

    proc_free(donor);
    proc_free(parent);
    proc_free(child);
    return 0;
}
DEFINE_SELFTEST(cap_revoke_delegate_revokes_spawned_child,
                selftest_cap_revoke_delegate_revokes_spawned_child);

static i32 selftest_cap_mutex_token_drop(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i32 object_index = sync_mutex_alloc(p);
    assert(object_index >= 0);
    i32 handle = cap_open_handle(p, (u16) object_index, CAP_TYPE_MUTEX,
                                 CAP_RIGHT_WRITE, 5, true);
    assert(handle == 5);

    i64 token = cap_get_token(p, handle, CAP_TYPE_MUTEX);
    assert(token > 0);
    assert(cap_drop_token(p, (u64) token) == 0);
    assert(!cap_slot_read(p, handle).valid);
    assert(!sync_mutex_get(object_index));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_mutex_token_drop, selftest_cap_mutex_token_drop);

/* Validate the cap_lookup_object active-use pin lifecycle:
 * (1) lookup bumps refcount above 1 so an intervening drop cannot free
 *     the underlying primitive,
 * (2) cap_put_ref decrements; the next drop frees,
 * (3) without cap_put_ref the slot stays alive (refcount remains > 0).
 */
static i32 selftest_cap_lookup_object_pins_sync(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i32 object_index = sync_mutex_alloc(p);
    assert(object_index >= 0);
    i32 handle = cap_open_handle(p, (u16) object_index, CAP_TYPE_MUTEX,
                                 CAP_RIGHT_WRITE, 5, true);
    assert(handle == 5);

    /* Pin via cap_lookup_object, then concurrently drop the token. The
     * underlying mutex must stay live until cap_put_ref runs.
     */
    struct cap_ref ref =
        cap_lookup_object(p, handle, CAP_RIGHT_WRITE, CAP_TYPE_MUTEX);
    assert(ref.type == CAP_TYPE_MUTEX);

    i64 token = cap_get_token(p, handle, CAP_TYPE_MUTEX);
    assert(token > 0);
    assert(cap_drop_token(p, (u64) token) == 0);
    /* The cap slot is gone, but the pinned object survives. */
    assert(!cap_slot_read(p, handle).valid);
    assert(sync_mutex_get(object_index));

    /* Release the pin -- now the underlying primitive is destroyed. */
    cap_put_ref(&ref);
    assert(sync_mutex_get(object_index) == NULL);
    assert(ref.type == CAP_TYPE_NONE);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_lookup_object_pins_sync,
                selftest_cap_lookup_object_pins_sync);

static i32 selftest_cap_thread_slots_are_reserved(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i32 object_index = posix_timer_alloc(p);
    assert(object_index >= 0);

    i32 reserved_slot = CAP_SPACE_SLOTS - 1;
    assert(cap_open_timer(p, (u16) object_index,
                          CAP_RIGHT_READ | CAP_RIGHT_WRITE, reserved_slot,
                          true) == -(i32) EBADF);
    assert(posix_timer_ptr((u16) object_index)->in_use);
    posix_timer_put_idx((u16) object_index);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_thread_slots_are_reserved,
                selftest_cap_thread_slots_are_reserved);

static i32 selftest_cap_dup_reserved_slot_preserves_thread_handle(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    /* sched_task carries an embedded kernel stack and guard page; allocate it
     * on the kvalloc heap rather than the selftest task's own stack to avoid
     * overflowing into the guard.
     */
    struct option_byte_array td_mem =
        kvalloc_alloc(sizeof(struct sched_task), alignof(struct sched_task));
    assert(!td_mem.is_none);
    struct byte_array td_ba = option_byte_array_checked(td_mem);
    struct sched_task *td = byte_array_ptr(td_ba);
    memset(td, 0, sizeof(*td));

    td->proc = p;
    {
        u64 flags = proc_table_lock_irqsave();
        assert(proc_attach_task(p, td));
        proc_table_unlock_irqrestore(flags);
    }

    u8 thread_slot = proc_task_slot(p, td);
    i32 reserved_slot = CAP_SPACE_SLOTS - PROC_THREAD_MAX + (i32) thread_slot;
    i32 thread_handle =
        cap_open_handle(p, thread_slot, CAP_TYPE_THREAD,
                        CAP_RIGHT_READ | CAP_RIGHT_WRITE, reserved_slot, true);
    assert(thread_handle == reserved_slot);
    td->td_cap_slot = (i16) thread_handle;

    i64 thread_token = cap_get_token(p, thread_handle, CAP_TYPE_THREAD);
    assert(thread_token > 0);
    assert(cap_dup_fd(p, PROC_FD_STDOUT, thread_handle, true) == -(i32) EBADF);
    assert(cap_get_token(p, thread_handle, CAP_TYPE_THREAD) == thread_token);

    /* Detach the dummy task so proc_free sees an empty task list, then release
     * the heap-allocated task storage.
     */
    {
        u64 flags = proc_table_lock_irqsave();
        proc_detach_task(p, td);
        proc_table_unlock_irqrestore(flags);
    }
    kvalloc_free(td_ba);
    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_dup_reserved_slot_preserves_thread_handle,
                selftest_cap_dup_reserved_slot_preserves_thread_handle);

/* Token slot_index spans bits 40..47 (8 bits). Setting bit 47 in an otherwise
 * valid token must yield an out-of-range slot and reject the lookup; the
 * earlier mask collapsed bit 47 to a live alias.
 */
static i32 selftest_cap_token_slot_bit47_rejected(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i64 token = cap_get_token(p, PROC_FD_STDOUT, CAP_TYPE_FD);
    assert(token > 0);

    u64 aliased = (u64) token | ((u64) 1 << 47);
    assert(aliased != (u64) token);
    /* The aliased token must NOT validate; cap_drop_token returns EBADF. */
    assert(cap_drop_token(p, aliased) == -(i64) EBADF);
    /* Original cap is still live. */
    assert(cap_fd_is_valid(p, PROC_FD_STDOUT));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_token_slot_bit47_rejected,
                selftest_cap_token_slot_bit47_rejected);

static i32 selftest_cap_mqueue_token_drop(void)
{
    struct proc *p = proc_alloc();
    assert(p);

    i32 object_index = mqueue_open(p, 4, 16);
    assert(object_index >= 0);
    i32 handle = cap_open_handle(p, (u16) object_index, CAP_TYPE_MQUEUE,
                                 CAP_RIGHT_READ | CAP_RIGHT_WRITE, 6, true);
    assert(handle == 6);

    i64 token = cap_get_token(p, handle, CAP_TYPE_MQUEUE);
    assert(token > 0);
    assert(cap_drop_token(p, (u64) token) == 0);
    assert(!cap_slot_read(p, handle).valid);
    assert(mqueue_close(object_index) == -(i32) EBADF);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(cap_mqueue_token_drop, selftest_cap_mqueue_token_drop);
