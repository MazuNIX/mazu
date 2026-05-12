/* SPDX-License-Identifier: MIT */
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/selftest.h>

static i32 selftest_proc_alloc_free(void)
{
    struct proc *p = proc_alloc();
    assert(p);
    assert(p->magic == PROC_MAGIC);
    assert(p->state == PROC_STATE_EMBRYO);
    assert(p->pid > 0);
    u16 pid = p->pid;
    u32 gen_before = p->generation;
    assert(proc_find(pid) == p);
    proc_free(p);
    assert(p->state == PROC_STATE_FREE);
    assert(p->magic == 0xDEADDEADU);         /* poisoned after free */
    assert(p->generation == gen_before + 1); /* generation incremented */
    assert(proc_find(pid) == NULL);
    return 0;
}
DEFINE_SELFTEST(proc_alloc_free, selftest_proc_alloc_free);

static i32 selftest_proc_cap_fd_slots(void)
{
    struct proc *p = proc_alloc();
    assert(p);
    assert(cap_fd_is_valid(p, PROC_FD_STDIN));
    assert(cap_fd_is_valid(p, PROC_FD_STDOUT));
    assert(cap_fd_is_valid(p, PROC_FD_STDERR));
    for (sz i = PROC_FD_STDERR + 1; i < PROC_FD_MAX; i++)
        assert(!cap_fd_is_valid(p, (i32) i));
    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(proc_cap_fd_slots, selftest_proc_cap_fd_slots);

static i32 selftest_proc_pid_wrap_collision(void)
{
    u16 old_next_pid = next_pid;
    next_pid = U16_MAX;

    struct proc *p1 = proc_alloc();
    struct proc *p2 = proc_alloc();
    assert(p1);
    assert(p2);
    assert(p1->pid == U16_MAX);
    assert(p2->pid == 1);
    assert(p1->pid != p2->pid);

    proc_free(p1);
    proc_free(p2);
    next_pid = old_next_pid;
    return 0;
}
DEFINE_SELFTEST(proc_pid_wrap_collision, selftest_proc_pid_wrap_collision);

static i32 selftest_proc_vma_tracking(void)
{
    struct proc *p = proc_alloc();
    assert(p);
    assert(p->n_vmas == 0);

    /* Register a code VMA at USER_CODE_BASE, 2 pages. */
    i32 rc = proc_add_vma(p, USER_CODE_BASE, 2UL * PAGE_SIZE,
                          VMA_PERM_READ | VMA_PERM_EXEC);
    assert(rc == 0);
    assert(p->n_vmas == 1);

    /* Register a stack VMA. */
    rc = proc_add_vma(p, (ptr) (USER_STACK_TOP - 4UL * PAGE_SIZE),
                      4UL * PAGE_SIZE, VMA_PERM_READ | VMA_PERM_WRITE);
    assert(rc == 0);
    assert(p->n_vmas == 2);

    /* Address inside code VMA should be found. */
    assert(proc_vma_contains(p, USER_CODE_BASE + 0x100, 0x10));

    /* Address inside stack VMA should be found. */
    assert(proc_vma_contains(p, (ptr) (USER_STACK_TOP - PAGE_SIZE), 0x10));

    /* Address outside any VMA should NOT be found. */
    assert(!proc_vma_contains(p, USER_DATA_BASE, 0x10));

    /* Zero-length access is always valid. */
    assert(proc_vma_contains(p, 0, 0));

    /* Cross-VMA boundary should fail. */
    assert(!proc_vma_contains(p, USER_CODE_BASE + PAGE_SIZE, 2UL * PAGE_SIZE));

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(proc_vma_tracking, selftest_proc_vma_tracking);

static i32 selftest_proc_state_machine(void)
{
    struct proc *p = proc_alloc();
    assert(p);
    assert(p->state == PROC_STATE_EMBRYO);

    /* EMBRYO -> RUNNING */
    proc_set_state(p, PROC_STATE_RUNNING);
    assert(p->state == PROC_STATE_RUNNING);

    /* RUNNING -> ZOMBIE */
    proc_set_state(p, PROC_STATE_ZOMBIE);
    assert(p->state == PROC_STATE_ZOMBIE);

    /* ZOMBIE -> FREE (via proc_free) */
    proc_free(p);
    assert(p->state == PROC_STATE_FREE);

    return 0;
}
DEFINE_SELFTEST(proc_state_machine, selftest_proc_state_machine);

static i32 selftest_proc_sleeping_transition(void)
{
    struct proc *p = proc_alloc();
    assert(p);
    proc_set_state(p, PROC_STATE_RUNNING);

    proc_set_state(p, PROC_STATE_SLEEPING);
    assert(p->state == PROC_STATE_SLEEPING);

    proc_set_state(p, PROC_STATE_RUNNING);
    assert(p->state == PROC_STATE_RUNNING);

    /* Cleanup. */
    proc_set_state(p, PROC_STATE_ZOMBIE);
    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(proc_sleeping_transition, selftest_proc_sleeping_transition);

static i32 selftest_proc_reparent_orphan(void)
{
    /* Allocate "init" (PID 1) as the reparent target. */
    u16 save_next = next_pid;
    next_pid = 1;
    struct proc *init = proc_alloc();
    assert(init);
    assert(init->pid == 1);
    proc_set_state(init, PROC_STATE_RUNNING);

    /* Allocate parent and two children. */
    struct proc *parent = proc_alloc();
    assert(parent);
    proc_set_state(parent, PROC_STATE_RUNNING);

    struct proc *c1 = proc_alloc();
    assert(c1);
    c1->parent_pid = parent->pid;
    c1->parent_generation = parent->generation;
    proc_set_state(c1, PROC_STATE_RUNNING);

    struct proc *c2 = proc_alloc();
    assert(c2);
    c2->parent_pid = parent->pid;
    c2->parent_generation = parent->generation;
    proc_set_state(c2, PROC_STATE_RUNNING);

    assert(proc_count_children(parent->pid) == 2);

    /* Parent exits; children should be reparented to PID 1. */
    proc_reparent_children(parent);

    assert(c1->parent_pid == 1);
    assert(c2->parent_pid == 1);
    assert(proc_count_children(init->pid) == 2);
    assert(proc_count_children(parent->pid) == 0);

    /* Cleanup. */
    proc_set_state(c1, PROC_STATE_ZOMBIE);
    proc_free(c1);
    proc_set_state(c2, PROC_STATE_ZOMBIE);
    proc_free(c2);
    proc_set_state(parent, PROC_STATE_ZOMBIE);
    proc_free(parent);
    proc_set_state(init, PROC_STATE_ZOMBIE);
    proc_free(init);
    next_pid = save_next;
    return 0;
}
DEFINE_SELFTEST(proc_reparent_orphan, selftest_proc_reparent_orphan);

static i32 selftest_proc_reparent_zombie(void)
{
    u16 save_next = next_pid;
    next_pid = 1;
    struct proc *init = proc_alloc();
    assert(init && init->pid == 1);
    proc_set_state(init, PROC_STATE_RUNNING);

    struct proc *parent = proc_alloc();
    assert(parent);
    proc_set_state(parent, PROC_STATE_RUNNING);

    struct proc *child = proc_alloc();
    assert(child);
    child->parent_pid = parent->pid;
    child->parent_generation = parent->generation;
    proc_set_state(child, PROC_STATE_RUNNING);
    proc_set_state(child, PROC_STATE_ZOMBIE); /* child died first */
    u16 child_pid = child->pid;

    /* Parent exits; zombie child should be reparented to init. */
    proc_reparent_children(parent);
    assert(child->parent_pid == 1);
    assert(proc_count_children(init->pid) == 1);

    /* Verify child is still findable as zombie under init. */
    struct proc *found = proc_find(child_pid);
    assert(found == child);
    assert(found->state == PROC_STATE_ZOMBIE);

    /* Cleanup: free zombie child, then parent and init. */
    proc_free(child);
    proc_set_state(parent, PROC_STATE_ZOMBIE);
    proc_free(parent);
    proc_set_state(init, PROC_STATE_ZOMBIE);
    proc_free(init);
    next_pid = save_next;
    return 0;
}
DEFINE_SELFTEST(proc_reparent_zombie, selftest_proc_reparent_zombie);

/* Test multi-child wait: spawn 3 children, make zombies, wait all. */
static i32 selftest_proc_multi_child_wait(void)
{
    struct proc *parent = proc_alloc();
    assert(parent);
    proc_set_state(parent, PROC_STATE_RUNNING);

    struct proc *children[3];
    for (sz i = 0; i < 3; i++) {
        children[i] = proc_alloc();
        assert(children[i]);
        children[i]->parent_pid = parent->pid;
        children[i]->parent_generation = parent->generation;
        proc_set_state(children[i], PROC_STATE_RUNNING);
    }

    /* All children exit (become zombies). */
    for (sz i = 0; i < 3; i++) {
        children[i]->exit_code = (i32) (10 + i);
        proc_set_state(children[i], PROC_STATE_ZOMBIE);
    }

    /* Wait for all 3 children via proc_wait_child. */
    for (sz i = 0; i < 3; i++) {
        u16 pid;
        i32 code;
        i32 rc = proc_wait_child(parent, &pid, &code);
        assert(rc == 0);
        assert(pid > 0);
    }

    /* No more children -> ECHILD. */
    u16 pid;
    i32 code;
    assert(proc_wait_child(parent, &pid, &code) == -(i32) ECHILD);

    proc_set_state(parent, PROC_STATE_ZOMBIE);
    proc_free(parent);
    return 0;
}
DEFINE_SELFTEST(proc_multi_child_wait, selftest_proc_multi_child_wait);

/* Test proc_exit: full exit sequence with reparenting. */
static i32 selftest_proc_exit_lifecycle(void)
{
    struct proc *parent = proc_alloc();
    assert(parent);
    proc_set_state(parent, PROC_STATE_RUNNING);

    struct proc *child = proc_alloc();
    assert(child);
    child->parent_pid = parent->pid;
    child->parent_generation = parent->generation;
    proc_set_state(child, PROC_STATE_RUNNING);

    u16 child_pid = child->pid;

    /* Child exits via proc_exit. */
    proc_exit(child, 42);

    /* Child should be zombie (parent is alive). */
    struct proc *found = proc_find(child_pid);
    assert(found == child);
    assert(found->state == PROC_STATE_ZOMBIE);
    assert(found->exit_code == 42);

    /* Parent reaps. */
    u16 pid;
    i32 code;
    i32 rc = proc_wait_child(parent, &pid, &code);
    assert(rc == 0);
    assert(pid == child_pid);
    assert(code == 42);

    /* Child slot now FREE and unreachable. */
    assert(proc_find(child_pid) == NULL);

    proc_set_state(parent, PROC_STATE_ZOMBIE);
    proc_free(parent);
    return 0;
}
DEFINE_SELFTEST(proc_exit_lifecycle, selftest_proc_exit_lifecycle);

/* Test resource cleanup: proc slot is reusable after proc_exit + wait. */
static i32 selftest_proc_slot_reuse(void)
{
    struct proc *parent = proc_alloc();
    assert(parent);
    proc_set_state(parent, PROC_STATE_RUNNING);

    struct proc *child = proc_alloc();
    assert(child);
    child->parent_pid = parent->pid;
    child->parent_generation = parent->generation;
    proc_set_state(child, PROC_STATE_RUNNING);

    u32 gen = child->generation;

    proc_exit(child, 0);

    u16 pid;
    i32 code;
    proc_wait_child(parent, &pid, &code);

    /* After reap, the slot should be FREE with incremented generation. */
    assert(child->state == PROC_STATE_FREE);
    assert(child->generation == gen + 1);

    /* Can allocate again in that slot. */
    struct proc *reused = proc_alloc();
    assert(reused);
    /* The allocator may or may not give us the same slot, but the table
     * should have capacity.
     */
    proc_free(reused);

    proc_set_state(parent, PROC_STATE_ZOMBIE);
    proc_free(parent);
    return 0;
}
DEFINE_SELFTEST(proc_slot_reuse, selftest_proc_slot_reuse);

/* Test proc_count_children counts correctly. */
static i32 selftest_proc_count_children(void)
{
    struct proc *parent = proc_alloc();
    assert(parent);
    proc_set_state(parent, PROC_STATE_RUNNING);

    assert(proc_count_children(parent->pid) == 0);

    struct proc *c1 = proc_alloc();
    assert(c1);
    c1->parent_pid = parent->pid;
    c1->parent_generation = parent->generation;
    proc_set_state(c1, PROC_STATE_RUNNING);
    assert(proc_count_children(parent->pid) == 1);

    struct proc *c2 = proc_alloc();
    assert(c2);
    c2->parent_pid = parent->pid;
    c2->parent_generation = parent->generation;
    proc_set_state(c2, PROC_STATE_RUNNING);
    assert(proc_count_children(parent->pid) == 2);

    /* Zombie still counts. */
    proc_set_state(c1, PROC_STATE_ZOMBIE);
    assert(proc_count_children(parent->pid) == 2);

    /* Free removes from count. */
    proc_free(c1);
    assert(proc_count_children(parent->pid) == 1);

    proc_set_state(c2, PROC_STATE_ZOMBIE);
    proc_free(c2);
    assert(proc_count_children(parent->pid) == 0);

    proc_set_state(parent, PROC_STATE_ZOMBIE);
    proc_free(parent);
    return 0;
}
DEFINE_SELFTEST(proc_count_children, selftest_proc_count_children);

/* Verify the bounded per-process task list: a fresh proc has zero tasks
 * and no leader, attach + detach round-trip preserves invariants, the
 * list rejects overflow, and the leader accessor matches.  Today
 * PROC_THREAD_MAX is 1; the test still exercises the second-attach path
 * to lock the bound in for future-proofing.
 *
 * The dummies are heap-allocated rather than stack-allocated because
 * struct sched_task carries an embedded kernel stack and guard page;
 * two of them on the test task's stack would overflow it.
 */
static i32 selftest_proc_task_list(void)
{
    struct proc *p = proc_alloc();
    assert(p);
    assert(p->n_tasks == 0);
    assert(proc_thread_group_leader(p) == NULL);
    /* Transition to RUNNING so proc_reserve_thread_slot accepts the
     * proc; that helper rejects EMBRYO / ZOMBIE / FREE intentionally
     * to prevent reservations against half-constructed or exiting
     * processes.
     */
    proc_set_state(p, PROC_STATE_RUNNING);

    struct option_byte_array a_mem =
        kvalloc_alloc(sizeof(struct sched_task), alignof(struct sched_task));
    struct option_byte_array b_mem =
        kvalloc_alloc(sizeof(struct sched_task), alignof(struct sched_task));
    assert(!a_mem.is_none);
    assert(!b_mem.is_none);
    struct byte_array a_ba = option_byte_array_checked(a_mem);
    struct byte_array b_ba = option_byte_array_checked(b_mem);
    struct sched_task *dummy_a = byte_array_ptr(a_ba);
    struct sched_task *dummy_b = byte_array_ptr(b_ba);
    memset(dummy_a, 0, sizeof(*dummy_a));
    memset(dummy_b, 0, sizeof(*dummy_b));

    /* First attach (n_tasks == 0) bypasses the reservation requirement;
     * proc_attach_task picks slot 0 and elects the leader.
     */
    u64 flags = proc_table_lock_irqsave();
    bool ok = proc_attach_task(p, dummy_a);
    proc_table_unlock_irqrestore(flags);
    assert(ok);
    assert(p->n_tasks == 1);
    assert(proc_thread_group_leader(p) == dummy_a);

    /* Subsequent attaches (n_tasks > 0) require a slot reservation
     * first. proc_reserve_thread_slot picks the lowest free slot under
     * lock; proc_attach_task_slot consumes that reservation.
     */
    u8 slot = PROC_THREAD_MAX;
    flags = proc_table_lock_irqsave();
    ok = proc_reserve_thread_slot(p, &slot);
    proc_table_unlock_irqrestore(flags);
    assert(ok);
    assert(slot < PROC_THREAD_MAX);

    flags = proc_table_lock_irqsave();
    ok = proc_attach_task_slot(p, dummy_b, slot);
    proc_table_unlock_irqrestore(flags);
    assert(ok);
    assert(p->n_tasks == 2);
    assert(proc_thread_group_leader(p) == dummy_a);

    /* Detach the leader; dummy_b is still attached. proc_thread_group_
     * leader migrates to the next live slot.
     */
    dummy_a->proc = p;
    flags = proc_table_lock_irqsave();
    proc_detach_task(p, dummy_a);
    proc_table_unlock_irqrestore(flags);
    assert(p->n_tasks == 1);
    assert(dummy_a->proc == NULL);

    flags = proc_table_lock_irqsave();
    proc_detach_task(p, dummy_b);
    proc_table_unlock_irqrestore(flags);
    assert(p->n_tasks == 0);
    assert(proc_thread_group_leader(p) == NULL);

    /* Detaching a task that is not in the list is a no-op. */
    flags = proc_table_lock_irqsave();
    proc_detach_task(p, dummy_b);
    proc_table_unlock_irqrestore(flags);
    assert(p->n_tasks == 0);

    /* Re-attach after detach: the slot must be reusable.  Verifies the
     * detach path leaves leader_idx in a state where the next attach
     * picks the freed slot back up.
     */
    flags = proc_table_lock_irqsave();
    ok = proc_attach_task(p, dummy_b);
    proc_table_unlock_irqrestore(flags);
    assert(ok);
    assert(p->n_tasks == 1);
    assert(proc_thread_group_leader(p) == dummy_b);

    flags = proc_table_lock_irqsave();
    proc_detach_task(p, dummy_b);
    proc_table_unlock_irqrestore(flags);
    assert(p->n_tasks == 0);
    assert(proc_thread_group_leader(p) == NULL);

    kvalloc_free(a_ba);
    kvalloc_free(b_ba);
    proc_set_state(p, PROC_STATE_ZOMBIE);
    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(proc_task_list, selftest_proc_task_list);
