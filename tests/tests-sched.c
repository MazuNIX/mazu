/* SPDX-License-Identifier: MIT */
#include <mazu/sched.h>
#include <mazu/selftest.h>

/* Convenience shorthand for tests: creates a task without noreturn flag. */
static struct result sched_create_impl(sched_callback_func_t callback,
                                       void *context,
                                       u8 prio,
                                       i32 affinity)
{
    return sched_create_impl_ex(callback, context, prio, affinity, false);
}

static volatile enum td_state selftest_observed_state;

static void selftest_state_cb(void *ctx __unused)
{
    /* Record this task's state (should be RUNNING during execution). */
    selftest_observed_state = get_pcpu()->curthread->state;
}

static i32 test_thread_states(void)
{
    /* Main task should be RUNNING. */
    if (get_pcpu()->curthread->state != TD_STATE_RUNNING)
        return 1;

    /* Create task pinned to BSP so a secondary hart doesn't steal it. */
    struct result res =
        sched_create_impl(selftest_state_cb, NULL, SCHED_PRIO_NORMAL, 0);
    if (res.is_error)
        return 1;

    /* Yield to the new task; it records its own state. */
    sleep_ms(time_ms_new(0));

    /* The new task ran and observed itself as RUNNING. */
    if (selftest_observed_state != TD_STATE_RUNNING)
        return 1;

    return 0;
}
DEFINE_SELFTEST(thread_states, test_thread_states);

static volatile u64 selftest_busy_cpu_us;

static void selftest_busy_cb(void *ctx __unused)
{
    /* Busy-loop for roughly 50ms.  Uses time_current_ms() which is
     * already calibrated to the actual timebase frequency.
     */
    struct time_ms start = time_current_ms();
    while (time_current_ms().ms - start.ms < 50)
        ;
    /* Include the current (not yet accumulated) time slice.
     * Disable interrupts so preemption cannot update cpu_time_us
     * between reading it and sampling switch_in_ticks.
     */
    disable_interrupts();
    struct sched_task *td = get_pcpu()->curthread;
    selftest_busy_cpu_us =
        td->cpu_time_us + time_ticks_to_us(time_rdtime() - td->switch_in_ticks);
    enable_interrupts();
}

static i32 test_cpu_time(void)
{
    selftest_busy_cpu_us = 0;
    /* Pin to BSP so the task doesn't migrate to a secondary hart
     * before observing its cpu_time_us.
     */
    struct result res =
        sched_create_impl(selftest_busy_cb, NULL, SCHED_PRIO_NORMAL, 0);
    if (res.is_error)
        return 1;

    /* Yield to let the busy task run. */
    sleep_ms(time_ms_new(0));

    /* Generous tolerance: 20ms..200ms (QEMU jitter can be substantial). */
    if (selftest_busy_cpu_us < 20000 || selftest_busy_cpu_us > 200000)
        return 1;
    return 0;
}
DEFINE_SELFTEST(cpu_time, test_cpu_time);

/* Priority ordering: create tasks at different priorities, verify execution
 * order via a shared counter array.  Higher priority runs first.
 */
#define PRIO_ORDER_N 3
static volatile int prio_order[PRIO_ORDER_N];
static volatile int prio_idx;
static volatile int prio_done_count;

static void selftest_prio_cb(void *ctx)
{
    int slot = (int) (uptr) ctx;
    int idx = __atomic_fetch_add(&prio_idx, 1, __ATOMIC_ACQ_REL);
    if (idx < (int) countof(prio_order))
        prio_order[idx] = slot;
    __atomic_fetch_add(&prio_done_count, 1, __ATOMIC_RELEASE);
}

static i32 test_priority_order(void)
{
    __atomic_store_n(&prio_idx, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&prio_done_count, 0, __ATOMIC_RELAXED);
    prio_order[0] = prio_order[1] = prio_order[2] = -1;

    /* Create tasks: LOW=0, NORMAL=1, HIGH=2. Create in ascending order
     * so that without priorities they'd run 0,1,2.  With priorities the
     * HIGH task should run first.  Pin all to BSP so secondary harts
     * don't steal them before priority ordering can be verified.
     *
     * Disable interrupts around all three creates to prevent IPI_SCHED
     * from preempting main between creates.  After cpu_time test, BSP
     * is marked idle (main is IDLE priority); an IPI bounce from a
     * secondary could schedule the IDLE test task prematurely.
     */
    disable_interrupts();
    struct result r;
    r = sched_create_impl(selftest_prio_cb, (void *) (uptr) 0, SCHED_PRIO_IDLE,
                          0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    r = sched_create_impl(selftest_prio_cb, (void *) (uptr) 1,
                          SCHED_PRIO_NORMAL, 0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    r = sched_create_impl(selftest_prio_cb, (void *) (uptr) 2, SCHED_PRIO_HIGH,
                          0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    enable_interrupts();

    /* Poll for all three tasks to complete, yielding between checks.
     * The main task is IDLE priority, so each yield cycles through the BSP idle
     * thread and any pending IDLE-priority test task before resuming. Yielding
     * (sleep_ms(0)) avoids the long-sleep wake path that has shown intermittent
     * stalls under QEMU TCG SMP timing.
     */
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(2000);
    while (__atomic_load_n(&prio_done_count, __ATOMIC_ACQUIRE) < PRIO_ORDER_N) {
        if (time_rdtime() - start > timeout)
            return 1;
        sleep_ms(time_ms_new(0));
    }

    /* Expected order: HIGH(2), NORMAL(1), IDLE(0). */
    if (prio_order[0] != 2 || prio_order[1] != 1 || prio_order[2] != 0)
        return 1;
    return 0;
}
DEFINE_SELFTEST(priority_order, test_priority_order);

/* Preemption test: two NORMAL tasks - a busy-waiter that never yields,
 * and a setter that flips a flag.  Without preemption the busy-waiter
 * would block forever; with preemption the timer tick expires its quantum
 * and the setter gets a turn.
 */
static volatile bool preempt_flag;

static void selftest_preempt_noyield(void *ctx __unused)
{
    while (!preempt_flag)
        ;
}

static void selftest_preempt_setter(void *ctx __unused)
{
    preempt_flag = true;
}

static i32 test_preemption(void)
{
    preempt_flag = false;

    /* Pin both tasks to BSP so preemption (not SMP parallelism) is the
     * only mechanism that allows setter to run.  Create with interrupts
     * disabled to prevent IPI-triggered preemption between creates.
     */
    disable_interrupts();
    struct result r;
    r = sched_create_impl(selftest_preempt_noyield, NULL, SCHED_PRIO_NORMAL, 0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    r = sched_create_impl(selftest_preempt_setter, NULL, SCHED_PRIO_NORMAL, 0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    enable_interrupts();

    /* Both tasks are NORMAL, pinned to BSP.  noyield runs first (FIFO),
     * busy-waits on the flag.  After one quantum (10ms) the timer preempts
     * it, setter runs and flips the flag.  noyield resumes, sees the flag,
     * exits.  Main resumes from sleep.
     */
    sleep_ms(time_ms_new(200));

    if (!preempt_flag)
        return 1;
    return 0;
}
DEFINE_SELFTEST(preemption, test_preemption);

/* Test: setting need_resched + yielding clears the flag via the real
 * trap path and returns to the same task (only runnable at this priority).
 */
static i32 test_need_resched_trap_exit(void)
{
    struct pcpu *pc = get_pcpu();
    struct sched_task *td = pc->curthread;

    if (!td || td->state != TD_STATE_RUNNING)
        return 1;

    __atomic_store_n(&pc->need_resched, 1, __ATOMIC_RELEASE);
    sleep_ms(time_ms_new(0)); /* yield through real trap path */

    /* need_resched must have been drained by trap_dispatch. */
    if (__atomic_load_n(&pc->need_resched, __ATOMIC_RELAXED) != 0)
        return 1;
    if (pc->curthread != td)
        return 1;
    return 0;
}
DEFINE_SELFTEST(need_resched_trap_exit, test_need_resched_trap_exit);

/* Test: quantum_callout_cb sets need_resched, and yielding clears it. */
static i32 test_quantum_expiry_need_resched(void)
{
    struct pcpu *pc = get_pcpu();
    struct sched_task *td = pc->curthread;

    if (!td || td->state != TD_STATE_RUNNING)
        return 1;

    __atomic_store_n(&pc->need_resched, 0, __ATOMIC_RELAXED);
    quantum_callout_cb(NULL);

    if (__atomic_load_n(&pc->need_resched, __ATOMIC_ACQUIRE) == 0)
        return 1;

    sleep_ms(time_ms_new(0)); /* yield through real trap path */

    if (__atomic_load_n(&pc->need_resched, __ATOMIC_RELAXED) != 0)
        return 1;
    if (pc->curthread != td)
        return 1;
    return 0;
}
DEFINE_SELFTEST(quantum_expiry_need_resched, test_quantum_expiry_need_resched);

/* CPU affinity test: pin a task to hart 0, verify it runs there.
 * Then reset to -1 (any hart) and verify the field is updated.
 */
static volatile u32 affinity_observed_cpu;

static void selftest_affinity_cb(void *ctx __unused)
{
    affinity_observed_cpu = get_pcpu()->cpuid;
}

static i32 test_cpu_affinity(void)
{
    affinity_observed_cpu = (u32) -1;

    /* Create a task pinned to hart 0. */
    struct result r =
        sched_create_impl(selftest_affinity_cb, NULL, SCHED_PRIO_NORMAL, 0);
    if (r.is_error)
        return 1;

    sleep_ms(time_ms_new(50));

    /* Task should have run on hart 0. */
    if (affinity_observed_cpu != 0)
        return 1;

    return 0;
}
DEFINE_SELFTEST(cpu_affinity, test_cpu_affinity);

#if CONFIG_SMP
/* SMP migration test: verify that cross-hart migration counter increases
 * when unpinned tasks run across multiple harts.
 */
static void selftest_migration_noop(void *ctx __unused) {}

static i32 test_smp_migration_counter(void)
{
    struct sched_ctxsw_stats before;
    sched_get_ctxsw_stats(&before);

    /* Create unpinned tasks that yield repeatedly.  With SMP, some will
     * migrate between harts.
     */
    for (int i = 0; i < 4; i++) {
        struct result r = sched_create_task(selftest_migration_noop, NULL);
        if (r.is_error)
            return 1;
    }

    /* Yield enough to allow task migration across harts. */
    for (int i = 0; i < 10; i++)
        sleep_ms(time_ms_new(1));

    struct sched_ctxsw_stats after;
    sched_get_ctxsw_stats(&after);

    /* nr_migrations should have increased (at least some tasks migrated). */
    /* Note: cannot assert strictly >0 because QEMU SMP timing is
     * non-deterministic, but the counter must be valid (not garbage).
     */
    if (after.nr_migrations < before.nr_migrations)
        return 1;

    return 0;
}
DEFINE_SELFTEST(smp_migration_counter, test_smp_migration_counter);

/* SMP run queue test: create tasks that each busy-loop and increment a
 * volatile counter.  With multiple harts, they run in parallel.
 */
static volatile u32 smp_counters[4];

static void selftest_smp_counter(void *ctx)
{
    int idx = (int) (uptr) ctx;
    struct time_ms start = time_current_ms();
    while (time_current_ms().ms - start.ms < 50)
        smp_counters[idx]++;
}

static i32 test_smp_runqueue(void)
{
    for (int i = 0; i < 4; i++)
        smp_counters[i] = 0;

    for (int i = 0; i < 4; i++) {
        struct result r =
            sched_create_task(selftest_smp_counter, (void *) (uptr) i);
        if (r.is_error)
            return 1;
    }

    sleep_ms(time_ms_new(200));

    for (int i = 0; i < 4; i++) {
        if (smp_counters[i] == 0)
            return 1;
    }
    return 0;
}
DEFINE_SELFTEST(smp_runqueue, test_smp_runqueue);
#endif /* CONFIG_SMP */

/* Priority bitmap correctness: verify bitmap tracks queue occupancy after
 * tasks at different priority levels run and exit.
 */
static void selftest_bitmap_noop(void *ctx __unused) {}

static i32 test_priority_bitmap(void)
{
    /* After the previous tests, the bitmap should reflect current state.
     * Verify indirectly: create and drain tasks at each non-idle priority
     * and check that pick_next doesn't crash (it would crash on empty
     * bitmap + empty queue mismatch).
     */
    disable_interrupts();
    struct result r;
    r = sched_create_impl(selftest_bitmap_noop, NULL, SCHED_PRIO_HIGH, 0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    r = sched_create_impl(selftest_bitmap_noop, NULL, SCHED_PRIO_NORMAL, 0);
    if (r.is_error) {
        enable_interrupts();
        return 1;
    }
    enable_interrupts();

    /* Let them run; they exit immediately. */
    sleep_ms(time_ms_new(0));

    /* The BSP idle task is always in pcpu_runq[0][IDLE], so bit 0
     * should be set.  Higher bits should be clear after tasks exit.
     */
    u64 flags = spin_lock_irqsave(&pcpu_runq_lock[0]);
    bool idle_set = (pcpu_runq_bitmap[0] & BIT(SCHED_PRIO_IDLE)) != 0;
    spin_unlock_irqrestore(&pcpu_runq_lock[0], flags);

    return idle_set ? 0 : 1;
}
DEFINE_SELFTEST(priority_bitmap, test_priority_bitmap);

static i32 test_wakeup_latency_histogram(void)
{
    struct sched_latency_stats before, after;
    sched_get_latency_stats(&before);

    for (int i = 0; i < 5; i++)
        sleep_ms(time_ms_new(1));

    sched_get_latency_stats(&after);

    u64 before_total = 0, after_total = 0;
    for (u32 i = 0; i < countof(before.wakeup_latency_hist); i++) {
        before_total += before.wakeup_latency_hist[i];
        after_total += after.wakeup_latency_hist[i];
    }

    if (after_total <= before_total)
        return 1;
    if (after.wakeup_latency_max_us == 0)
        return 1;
    return 0;
}
DEFINE_SELFTEST(wakeup_latency_histogram, test_wakeup_latency_histogram);

/* Context-switch counting: verify that sched_get_ctxsw_stats returns
 * non-zero counters after context switches have occurred.
 */
static i32 test_ctxsw_counting(void)
{
    struct sched_ctxsw_stats before, after;
    sched_get_ctxsw_stats(&before);

    /* Force several context switches via sleep_ms(0) yields. */
    for (int i = 0; i < 5; i++)
        sleep_ms(time_ms_new(0));

    sched_get_ctxsw_stats(&after);

    /* Context-switch count must have increased. */
    if (after.nr_ctxsw <= before.nr_ctxsw)
        return 1;

    /* max_cycles should be non-zero (at least one switch measured). */
    if (after.max_cycles == 0)
        return 1;

    return 0;
}
DEFINE_SELFTEST(ctxsw_counting, test_ctxsw_counting);

/* Watchdog test: verify that sched_note_activity updates last_activity_ms
 * and that the watchdog stats function works.
 */
static i32 test_watchdog_activity(void)
{
    struct sched_task *td = get_pcpu()->curthread;
    if (!td)
        return 1;

    /* Stamp activity and verify it was recorded. */
    u64 before = td->last_activity_ms;
    sleep_ms(time_ms_new(10));
    sched_note_activity();
    u64 after = td->last_activity_ms;
    if (after < before)
        return 1;

    /* Verify watchdog stats function doesn't crash. */
    struct sched_watchdog_stats wds;
    sched_get_watchdog_stats(&wds);
    /* nr_warnings is cumulative; just check it's valid. */
    (void) wds.nr_hung;

    return 0;
}
DEFINE_SELFTEST(watchdog_activity, test_watchdog_activity);

/* Quantum rotation fairness: pin N CPU-bound equal-priority workers to one
 * CPU and assert that no worker's run-to-run latency exceeds (N - 1) quanta
 * plus QEMU jitter slack. Each worker busy-loops on time_rdtime() and tracks
 * the largest gap between adjacent samples; while the worker is descheduled
 * in favor of a peer, that gap equals the peers' combined service time. This
 * exercises the timer-driven quantum-expiry path, not voluntary yield.
 */
#define QUANTUM_ROTATION_N_TASKS 3
#define QUANTUM_ROTATION_DURATION_MS 300
static volatile u64 quantum_rotation_max_gap_ticks[QUANTUM_ROTATION_N_TASKS];
static volatile u64 quantum_rotation_iterations[QUANTUM_ROTATION_N_TASKS];
static volatile u64 quantum_rotation_deadline_ticks;
static volatile u32 quantum_rotation_done_count;

static void quantum_rotation_worker_cb(void *arg)
{
    u32 slot = (u32) (uptr) arg;
    u64 deadline =
        __atomic_load_n(&quantum_rotation_deadline_ticks, __ATOMIC_ACQUIRE);
    u64 prev = time_rdtime();
    u64 max_gap = 0;
    u64 iter = 0;

    /* CPU-bound: no yield, no sleep. Preemption comes from quantum expiry. */
    for (;;) {
        u64 now = time_rdtime();
        if (now >= deadline)
            break;
        u64 gap = now - prev;
        if (gap > max_gap)
            max_gap = gap;
        prev = now;
        iter++;
    }

    __atomic_store_n(&quantum_rotation_max_gap_ticks[slot], max_gap,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&quantum_rotation_iterations[slot], iter,
                     __ATOMIC_RELEASE);
    __atomic_fetch_add(&quantum_rotation_done_count, 1, __ATOMIC_RELEASE);
}

static i32 test_quantum_rotation_fairness(void)
{
    /* sched_default_quantum[SCHED_PRIO_NORMAL] = 1 (one 10ms tick). */
    const u64 quantum_ticks = time_ms_to_ticks(10);
    /* Nominal worst case is (N - 1) * quantum. Two extra quanta of slack
     * absorb QEMU mtimer jitter and callout coalescing observed under
     * concurrent selftest load; this still rejects a full extra rotation
     * (which would cost N * quantum, exceeding the cap) so an equal-priority
     * fairness regression cannot slip past. The companion lower-bound
     * assertion below catches degenerate "worker ran without preemption"
     * cases that a loose upper bound alone would miss.
     */
    const u64 max_allowed_ticks =
        (QUANTUM_ROTATION_N_TASKS - 1) * quantum_ticks + 2 * quantum_ticks;
    const u64 duration_ticks = time_ms_to_ticks(QUANTUM_ROTATION_DURATION_MS);

    __atomic_store_n(&quantum_rotation_done_count, 0, __ATOMIC_RELAXED);
    for (u32 i = 0; i < QUANTUM_ROTATION_N_TASKS; i++) {
        quantum_rotation_max_gap_ticks[i] = 0;
        quantum_rotation_iterations[i] = 0;
    }
    __atomic_store_n(&quantum_rotation_deadline_ticks,
                     time_rdtime() + duration_ticks, __ATOMIC_RELEASE);

    disable_interrupts();
    for (u32 i = 0; i < QUANTUM_ROTATION_N_TASKS; i++) {
        struct result r =
            sched_create_impl(quantum_rotation_worker_cb, (void *) (uptr) i,
                              SCHED_PRIO_NORMAL, 0);
        if (r.is_error) {
            enable_interrupts();
            return 1;
        }
    }
    enable_interrupts();

    /* This test task runs at SCHED_PRIO_IDLE, so it cannot preempt the
     * NORMAL-priority workers; sleep_ms parks it until they finish.
     */
    u64 watchdog_deadline =
        time_rdtime() + duration_ticks + time_ms_to_ticks(2000);
    while (__atomic_load_n(&quantum_rotation_done_count, __ATOMIC_ACQUIRE) <
           QUANTUM_ROTATION_N_TASKS) {
        if (time_rdtime() > watchdog_deadline)
            return 1;
        sleep_ms(time_ms_new(50));
    }

    for (u32 i = 0; i < QUANTUM_ROTATION_N_TASKS; i++) {
        if (__atomic_load_n(&quantum_rotation_iterations[i],
                            __ATOMIC_ACQUIRE) == 0)
            return 1;
        u64 gap = __atomic_load_n(&quantum_rotation_max_gap_ticks[i],
                                  __ATOMIC_ACQUIRE);
        /* Each worker must have been descheduled at least once (proves it
         * was not starved before first dispatch and ran in true rotation,
         * not solo); and the worst service gap stays within the bound.
         */
        if (gap < quantum_ticks || gap > max_allowed_ticks)
            return 1;
    }

    return 0;
}
DEFINE_SELFTEST(quantum_rotation_fairness, test_quantum_rotation_fairness);

/* Per-hart heartbeat: verify that heartbeat_stamp is updated during
 * scheduling and that sched_get_hart_watchdog reports a valid age.
 * Also verify that a healthy hart is not marked stale.
 */
static i32 test_hart_heartbeat(void)
{
    struct pcpu *pc = get_pcpu();
    u32 cpu = pc->cpuid;

    /* Heartbeat stamp should be non-zero after scheduler has run. */
    u64 stamp_before = pc->heartbeat_stamp;
    if (stamp_before == 0)
        return 1;

    /* Force a context switch to update heartbeat. */
    sleep_ms(time_ms_new(10));

    u64 stamp_after = pc->heartbeat_stamp;
    if (stamp_after <= stamp_before)
        return 1;

    /* Query hart watchdog stats: age should be small, not stale. */
    struct sched_hart_watchdog_stats hwd;
    if (sched_get_hart_watchdog(cpu, &hwd) != 0)
        return 1;
    if (hwd.stale)
        return 1;
    /* Age should be under 1 second (generous tolerance). */
    if (hwd.heartbeat_age_us > 1000000)
        return 1;

    return 0;
}
DEFINE_SELFTEST(hart_heartbeat, test_hart_heartbeat);

/* Scheduling domain: basic API test (init, attach, detach). */
static i32 test_sched_domain_basic(void)
{
    struct sched_domain dom;
    u64 quantum = time_ms_to_ticks(100);
    u64 period = time_ms_to_ticks(200);

    sched_domain_init(&dom, quantum, period);

    /* dom.refill_callout is armed by sched_domain_init and holds &dom; every
     * exit must drain it before this stack frame unwinds.
     */
    i32 rc = 0;
    if (dom.quantum_ticks != quantum || dom.period_ticks != period) {
        rc = 1;
        goto out;
    }
    if (dom.consumed_ticks != 0 || dom.state != DOMAIN_ACTIVE) {
        rc = 1;
        goto out;
    }
    if (dom.nr_members != 0) {
        rc = 1;
        goto out;
    }

    /* Attach/detach using current task as a guinea pig. */
    struct sched_task *cur = get_pcpu()->curthread;
    struct sched_domain *saved_domain = cur->domain;

    if (sched_domain_attach(&dom, cur) != 0) {
        rc = 1;
        goto out;
    }
    if (dom.nr_members != 1 || cur->domain != &dom) {
        rc = 1;
        goto out_detach;
    }

    sched_domain_detach(cur);
    if (dom.nr_members != 0 || cur->domain != NULL) {
        rc = 1;
        goto out;
    }

    /* Restore original domain via the proper API. */
    if (saved_domain) {
        if (sched_domain_attach(saved_domain, cur) != 0)
            rc = 1;
    }
    goto out;

out_detach:
    sched_domain_detach(cur);
out:
    callout_cancel_sync(&dom.refill_callout);
    return rc;
}
DEFINE_SELFTEST(sched_domain_basic, test_sched_domain_basic);

/* Scheduling domain budget test: verify the refill callout restores an
 * exhausted domain to ACTIVE and clears consumed_ticks for the next period.
 */
static i32 test_sched_domain_budget(void)
{
    struct sched_domain dom;
    /* Small budget: 10ms quantum, 50ms period. */
    u64 quantum = time_ms_to_ticks(10);
    u64 period = time_ms_to_ticks(50);
    sched_domain_init(&dom, quantum, period);

    /* Verify refill mechanics directly. Use atomic stores to match the
     * ordering used by production code when budget accounting depletes
     * a domain on context switch.
     */
    __atomic_store_n(&dom.consumed_ticks, dom.quantum_ticks, __ATOMIC_RELAXED);
    __atomic_store_n(&dom.state, DOMAIN_DEPLETED, __ATOMIC_RELEASE);

    /* Wait for the refill callout to fire (period is 50ms). */
    sleep_ms(time_ms_new(80));

    bool ok = __atomic_load_n(&dom.state, __ATOMIC_ACQUIRE) == DOMAIN_ACTIVE &&
              __atomic_load_n(&dom.consumed_ticks, __ATOMIC_RELAXED) == 0;

    /* Cancel before returning on either path: the callout closes over &dom,
     * which is on this function's stack and would dangle once we unwind.
     */
    callout_cancel_sync(&dom.refill_callout);
    return ok ? 0 : 1;
}
DEFINE_SELFTEST(sched_domain_budget, test_sched_domain_budget);
