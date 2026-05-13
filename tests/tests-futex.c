/* SPDX-License-Identifier: MIT */
/* Futex self-tests.
 *
 * Test 1: futex_wake on address with no waiters returns 0 (smoke test).
 * Test 2: futex_wake on a second address with no waiters returns 0.
 *
 * Note: futex_wait requires user-space mapping (copy_from_user), so
 * it cannot be exercised from kernel-only selftests.  These tests
 * verify the wake path and hash table initialization only.
 */

#include <kernel/sync/futex.h>
#include <mazu/selftest.h>
#include <mazu/uaccess.h>
#include "tests-proc-helpers.h"

/* Kernel-internal futex for testing: bypass copy_from_user. */

/* Test 1: FUTEX_WAIT value mismatch returns immediately. */
static volatile u32 futex_test_word;

static i32 test_futex_value_mismatch(void)
{
    futex_test_word = 42;
    /* Pass expected=99, which does not match 42 -> should return EAGAIN.
     * But futex_wait uses copy_from_user which requires user mapping.
     * For kernel-only testing, verify the hash and init instead.
     */
    (void) futex_test_word;
    /* Verify futex_init ran (table is accessible, no crash). */
    i64 rc = futex_wake((ptr) &futex_test_word, 1);
    if (rc != 0)
        return 1; /* no one waiting, should return 0 */
    return 0;
}
DEFINE_SELFTEST(futex_wake_empty, test_futex_value_mismatch);

/* Test 2: futex_wake on address with no waiters returns 0. */
static volatile u32 futex_test_word2;

static i32 test_futex_wake_none(void)
{
    futex_test_word2 = 0;
    i64 rc = futex_wake((ptr) &futex_test_word2, 10);
    if (rc != 0)
        return 1;
    return 0;
}
DEFINE_SELFTEST(futex_wake_none, test_futex_wake_none);

/* Tests 3-5: futex_cmp_requeue, futex_lock_pi, and futex_unlock_pi use
 * copy_from_user/copy_to_user internally, which reject kernel addresses
 * in S-mode selftests.  Verify the S-mode-accessible behavior:
 * kernel addresses produce -EFAULT, confirming the functions execute
 * through the locking path without deadlock or crash.
 */
static volatile u32 futex_requeue_src;
static volatile u32 futex_requeue_dst;

static i32 test_futex_cmp_requeue_efault(void)
{
    futex_requeue_src = 7;
    futex_requeue_dst = 0;
    i64 rc = futex_cmp_requeue((ptr) &futex_requeue_src, 7,
                               (ptr) &futex_requeue_dst, 1, 10);
    /* Kernel address -> copy_from_user returns -EFAULT. */
    if (rc != -(i64) EFAULT)
        return 1;
    return 0;
}
DEFINE_SELFTEST(futex_cmp_requeue_efault, test_futex_cmp_requeue_efault);

static volatile u32 futex_pi_word;

static i32 test_futex_lock_pi_efault(void)
{
    futex_pi_word = 0;
    i64 rc = futex_lock_pi((ptr) &futex_pi_word);
    if (rc != -(i64) EFAULT)
        return 1;
    return 0;
}
DEFINE_SELFTEST(futex_lock_pi_efault, test_futex_lock_pi_efault);

static i32 test_futex_unlock_pi_efault(void)
{
    futex_pi_word = 9999;
    i64 rc = futex_unlock_pi((ptr) &futex_pi_word);
    if (rc != -(i64) EFAULT)
        return 1;
    return 0;
}
DEFINE_SELFTEST(futex_unlock_pi_efault, test_futex_unlock_pi_efault);

static i32 test_futex_pi_owner_boost_internal(void)
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
    owner->td_base_prio = SCHED_PRIO_NORMAL;
    owner->td_prio = SCHED_PRIO_NORMAL;

    list_init(&waiter->pi_held_mutexes);
    list_init(&waiter->pi_held_futexes);
    waiter->td_base_prio = SCHED_PRIO_HIGH;
    waiter->td_prio = SCHED_PRIO_HIGH;
    waiter->state = TD_STATE_BLOCKED;

    struct futex_bucket bucket = {
        .lock = (spinlock_t) SPINLOCK_INITIALIZER,
    };
    list_init(&bucket.waiters);
    list_init(&bucket.pi_states);

    struct futex_pi_state *st =
        futex_pi_state_get_locked(&bucket, (ptr) 0x20000, true);
    if (!st) {
        free_mock_task(waiter);
        free_mock_task(owner);
        return 2;
    }

    futex_pi_link_owner_locked(st, owner);
    struct futex_waiter w = {
        .key = (ptr) 0x20000,
        .task = waiter,
        .bucket = &bucket,
        .pi_state = st,
        .pi_wait = true,
    };
    list_init(&w.node);
    list_add_tail(&bucket.waiters, &w.node);
    futex_pi_set_wait_dependency(waiter, st);
    futex_pi_recompute_owner_locked(&bucket, st);
    if (owner->td_prio != SCHED_PRIO_HIGH ||
        owner->td_futex_pi_prio != SCHED_PRIO_HIGH)
        return 3;

    list_del_init(&w.node);
    futex_pi_clear_wait_dependency(waiter);
    futex_pi_recompute_owner_locked(&bucket, st);
    if (owner->td_prio != SCHED_PRIO_NORMAL || owner->td_futex_pi_prio != 0)
        return 4;

    futex_pi_link_owner_locked(st, NULL);
    st->top_waiter_prio = 0;
    st->owner_died = false;
    futex_pi_state_maybe_free_locked(&bucket, st);
    free_mock_task(waiter);
    free_mock_task(owner);
    return 0;
}
DEFINE_SELFTEST(futex_pi_owner_boost_internal,
                test_futex_pi_owner_boost_internal);

static void futex_test_init_mock_task(struct sched_task *td,
                                      u8 base_prio,
                                      enum td_state state)
{
    list_init(&td->pi_held_mutexes);
    list_init(&td->pi_held_futexes);
    td->td_base_prio = base_prio;
    td->td_prio = base_prio;
    td->td_futex_pi_prio = 0;
    td->state = state;
}

static i32 test_futex_requeue_pi_transfers_donation_internal(void)
{
    struct sched_task *src_owner = alloc_mock_task();
    struct sched_task *dst_owner = alloc_mock_task();
    struct sched_task *waiter = alloc_mock_task();
    if (!src_owner || !dst_owner || !waiter) {
        if (src_owner)
            free_mock_task(src_owner);
        if (dst_owner)
            free_mock_task(dst_owner);
        if (waiter)
            free_mock_task(waiter);
        return 1;
    }

    futex_test_init_mock_task(src_owner, SCHED_PRIO_NORMAL, TD_STATE_RUNNING);
    futex_test_init_mock_task(dst_owner, SCHED_PRIO_IDLE, TD_STATE_RUNNING);
    futex_test_init_mock_task(waiter, SCHED_PRIO_HIGH, TD_STATE_BLOCKED);

    struct futex_bucket src = {
        .lock = (spinlock_t) SPINLOCK_INITIALIZER,
    };
    struct futex_bucket dst = {
        .lock = (spinlock_t) SPINLOCK_INITIALIZER,
    };
    list_init(&src.waiters);
    list_init(&src.pi_states);
    list_init(&dst.waiters);
    list_init(&dst.pi_states);

    struct futex_pi_state *src_state =
        futex_pi_state_get_locked(&src, (ptr) 0x21000, true);
    struct futex_pi_state *dst_state =
        futex_pi_state_get_locked(&dst, (ptr) 0x22000, true);
    if (!src_state || !dst_state) {
        free_mock_task(waiter);
        free_mock_task(dst_owner);
        free_mock_task(src_owner);
        return 2;
    }

    futex_pi_link_owner_locked(src_state, src_owner);
    futex_pi_link_owner_locked(dst_state, dst_owner);

    struct futex_waiter w = {
        .key = (ptr) 0x21000,
        .task = waiter,
        .bucket = &src,
        .pi_state = src_state,
        .pi_wait = true,
    };
    list_init(&w.node);
    list_add_tail(&src.waiters, &w.node);
    futex_pi_set_wait_dependency(waiter, src_state);
    futex_pi_recompute_owner_locked(&src, src_state);
    if (src_owner->td_prio != SCHED_PRIO_HIGH ||
        src_owner->td_futex_pi_prio != SCHED_PRIO_HIGH)
        return 3;

    list_del_init(&w.node);
    futex_pi_clear_wait_dependency(waiter);
    futex_pi_recompute_owner_locked(&src, src_state);
    if (src_owner->td_prio != SCHED_PRIO_NORMAL ||
        src_owner->td_futex_pi_prio != 0)
        return 4;

    w.key = (ptr) 0x22000;
    w.bucket = &dst;
    w.pi_state = dst_state;
    w.pi_wait = true;
    list_add_tail(&dst.waiters, &w.node);
    futex_pi_set_wait_dependency(waiter, dst_state);
    futex_pi_recompute_owner_locked(&dst, dst_state);
    if (dst_owner->td_prio != SCHED_PRIO_HIGH ||
        dst_owner->td_futex_pi_prio != SCHED_PRIO_HIGH)
        return 5;

    list_del_init(&w.node);
    futex_pi_clear_wait_dependency(waiter);
    futex_pi_recompute_owner_locked(&dst, dst_state);
    if (dst_owner->td_prio != SCHED_PRIO_IDLE ||
        dst_owner->td_futex_pi_prio != 0)
        return 6;

    futex_pi_link_owner_locked(src_state, NULL);
    futex_pi_link_owner_locked(dst_state, NULL);
    src_state->top_waiter_prio = 0;
    dst_state->top_waiter_prio = 0;
    src_state->owner_died = false;
    dst_state->owner_died = false;
    futex_pi_state_maybe_free_locked(&src, src_state);
    futex_pi_state_maybe_free_locked(&dst, dst_state);
    free_mock_task(waiter);
    free_mock_task(dst_owner);
    free_mock_task(src_owner);
    return 0;
}
DEFINE_SELFTEST(futex_requeue_pi_transfers_donation_internal,
                test_futex_requeue_pi_transfers_donation_internal);

static i32 test_futex_robust_clears_pi_boost(void)
{
    struct proc *p;
    struct sched_task *owner;
    if (!alloc_proc_and_task(&p, &owner))
        return 1;

    list_init(&owner->pi_held_mutexes);
    list_init(&owner->pi_held_futexes);
    owner->td_base_prio = SCHED_PRIO_NORMAL;
    owner->td_prio = SCHED_PRIO_NORMAL;
    owner->td_futex_pi_prio = 0;

    const vaddr_t va = USER_DATA_BASE + (141UL * PAGE_SIZE);
    if (proc_map_user_page(p, va, PT_FLAG_RW | PT_FLAG_USER).is_error) {
        free_proc_and_task(p, owner);
        return 2;
    }

    ptr next = 0;
    u32 futex_word = owner->id;
    if (copy_to_user(va, &next, sizeof(next)) < 0 ||
        copy_to_user(va + sizeof(ptr), &futex_word, sizeof(futex_word)) < 0) {
        free_proc_and_task(p, owner);
        return 3;
    }

    ptr futex_addr = (ptr) (va + sizeof(ptr));
    u32 idx = futex_hash(futex_addr);
    struct futex_bucket *b = &futex_table[idx];
    lockdep_acquire(LOCK_LEVEL_WAITQ);
    u64 flags = spin_lock_irqsave(&b->lock);
    struct futex_pi_state *st = futex_pi_state_get_locked(b, futex_addr, true);
    if (!st) {
        spin_unlock_irqrestore(&b->lock, flags);
        lockdep_release(LOCK_LEVEL_WAITQ);
        free_proc_and_task(p, owner);
        return 4;
    }
    st->top_waiter_prio = SCHED_PRIO_HIGH;
    futex_pi_link_owner_locked(st, owner);
    futex_pi_refresh_task_locked(owner);
    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);

    if (owner->td_prio != SCHED_PRIO_HIGH ||
        owner->td_futex_pi_prio != SCHED_PRIO_HIGH) {
        free_proc_and_task(p, owner);
        return 5;
    }

    owner->td_robust_list_head = 0;
    owner->td_robust_futex_offset = (i32) sizeof(ptr);
    owner->td_robust_pending = va;
    futex_exit_robust_list_task(owner);

    u32 out = 0;
    if (copy_from_user(&out, futex_addr, sizeof(out)) < 0 ||
        out != FUTEX_OWNER_DIED) {
        free_proc_and_task(p, owner);
        return 6;
    }
    if (owner->td_prio != SCHED_PRIO_NORMAL || owner->td_futex_pi_prio != 0) {
        free_proc_and_task(p, owner);
        return 7;
    }

    lockdep_acquire(LOCK_LEVEL_WAITQ);
    flags = spin_lock_irqsave(&b->lock);
    st = futex_pi_state_get_locked(b, futex_addr, false);
    bool ok = st && st->owner == NULL && st->owner_died;
    if (st) {
        st->owner_died = false;
        futex_pi_state_maybe_free_locked(b, st);
    }
    spin_unlock_irqrestore(&b->lock, flags);
    lockdep_release(LOCK_LEVEL_WAITQ);
    free_proc_and_task(p, owner);
    return ok ? 0 : 8;
}
DEFINE_SELFTEST(futex_robust_clears_pi_boost,
                test_futex_robust_clears_pi_boost);
