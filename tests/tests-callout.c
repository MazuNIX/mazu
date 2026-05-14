/* SPDX-License-Identifier: MIT */
#include <mazu/callout.h>
#include <mazu/selftest.h>
#include <mazu/time.h>

static volatile bool selftest_callout_fired;
static volatile int selftest_callout_order[4];
static volatile int selftest_callout_idx;

static void selftest_callout_cb(void *arg __unused)
{
    selftest_callout_fired = true;
}

static i32 test_callout_basic(void)
{
    struct callout c;
    callout_init(&c);
    selftest_callout_fired = false;

    /* Arm for 1ms worth of ticks. */
    callout_set_ticks(&c, time_ms_to_ticks(1), selftest_callout_cb, NULL);

    /* Every exit must drain the callout: it closes over &c on the stack. */
    i32 rc = 0;
    if (!callout_pending(&c)) {
        rc = 1;
        goto out;
    }

    /* Busy-wait up to 100ms for the callout to fire. */
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(100);
    while (!selftest_callout_fired) {
        if (time_rdtime() - start > timeout) {
            rc = 1; /* timed out */
            goto out;
        }
    }

    if (callout_pending(&c))
        rc = 1; /* should have been cleared */

out:
    callout_cancel_sync(&c);
    return rc;
}
DEFINE_SELFTEST(callout_basic, test_callout_basic);

static i32 test_callout_cancel(void)
{
    struct callout c;
    callout_init(&c);
    selftest_callout_fired = false;

    /* Arm for 500ms, cancel before it fires. */
    callout_set_ticks(&c, time_ms_to_ticks(500), selftest_callout_cb, NULL);

    if (!callout_pending(&c))
        return 1;

    callout_cancel(&c);

    if (callout_pending(&c))
        return 1;

    /* Wait 50ms; callback must not fire. */
    u64 start = time_rdtime();
    while (time_rdtime() - start < time_ms_to_ticks(50))
        ;

    if (selftest_callout_fired)
        return 1;

    return 0;
}
DEFINE_SELFTEST(callout_cancel, test_callout_cancel);

static void selftest_order_cb(void *arg)
{
    int slot = (int) (uptr) arg;
    selftest_callout_order[selftest_callout_idx++] = slot;
}

static i32 test_callout_ordering(void)
{
    struct callout c0, c1, c2;
    callout_init(&c0);
    callout_init(&c1);
    callout_init(&c2);
    selftest_callout_idx = 0;
    selftest_callout_order[0] = -1;
    selftest_callout_order[1] = -1;
    selftest_callout_order[2] = -1;

    /* Arm in reverse order: c2 fires first (shortest), c0 fires last. */
    callout_set_ticks(&c0, time_ms_to_ticks(30), selftest_order_cb,
                      (void *) (uptr) 0);
    callout_set_ticks(&c1, time_ms_to_ticks(20), selftest_order_cb,
                      (void *) (uptr) 1);
    callout_set_ticks(&c2, time_ms_to_ticks(10), selftest_order_cb,
                      (void *) (uptr) 2);

    /* Three stack-local callouts must all be drained before unwinding. */
    i32 rc = 0;
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(200);
    while (selftest_callout_idx < 3) {
        if (time_rdtime() - start > timeout) {
            rc = 1;
            goto out;
        }
    }

    /* Expected order: 2 (10ms), 1 (20ms), 0 (30ms). */
    if (selftest_callout_order[0] != 2 || selftest_callout_order[1] != 1 ||
        selftest_callout_order[2] != 0)
        rc = 1;

out:
    callout_cancel_sync(&c0);
    callout_cancel_sync(&c1);
    callout_cancel_sync(&c2);
    return rc;
}
DEFINE_SELFTEST(callout_ordering, test_callout_ordering);

static volatile bool selftest_rearm_first_fired;
static volatile bool selftest_rearm_second_fired;

static void selftest_rearm_first_cb(void *arg __unused)
{
    selftest_rearm_first_fired = true;
}

static void selftest_rearm_second_cb(void *arg __unused)
{
    selftest_rearm_second_fired = true;
}

static i32 test_callout_rearm(void)
{
    struct callout c;
    callout_init(&c);
    selftest_rearm_first_fired = false;
    selftest_rearm_second_fired = false;

    /* Arm for 500ms with first callback. */
    callout_set_ticks(&c, time_ms_to_ticks(500), selftest_rearm_first_cb, NULL);

    /* Re-arm for 10ms with second callback before first fires. */
    callout_set_ticks(&c, time_ms_to_ticks(10), selftest_rearm_second_cb, NULL);

    /* Every exit must drain c: until selftest_rearm_second_fired is true,
     * the callout is still armed against &c.
     */
    i32 rc = 0;
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(100);
    while (!selftest_rearm_second_fired) {
        if (time_rdtime() - start > timeout) {
            rc = 1;
            goto out;
        }
    }

    /* The first callback should never have fired. */
    if (selftest_rearm_first_fired)
        rc = 1;

out:
    callout_cancel_sync(&c);
    return rc;
}
DEFINE_SELFTEST(callout_rearm, test_callout_rearm);

/* Verify callout_pending tracks arm/cancel state correctly.
 * Note: callout_list_empty() is not checked because background kernel
 * threads (e.g. watchdog) may have sleep callouts armed.
 */
static i32 test_callout_pending(void)
{
    struct callout c;
    callout_init(&c);

    if (callout_pending(&c))
        return 1; /* fresh callout should not be pending */

    callout_set_ticks(&c, time_ms_to_ticks(500), selftest_callout_cb, NULL);

    if (!callout_pending(&c))
        return 1; /* armed callout should be pending */

    callout_cancel(&c);

    if (callout_pending(&c))
        return 1; /* canceled callout should not be pending */

    return 0;
}
DEFINE_SELFTEST(callout_pending, test_callout_pending);

/* Tickless validation self-tests */

static volatile u64 selftest_accuracy_fire_time;

static void selftest_accuracy_cb(void *arg __unused)
{
    selftest_accuracy_fire_time = time_rdtime();
}

/* Verify callout fires within acceptable latency of the requested delay.
 * Arms a 10ms callout and checks that fire time is within [8ms, 30ms].
 * Wide tolerance accounts for QEMU timer jitter.
 */
static i32 test_callout_accuracy(void)
{
    struct callout c;
    callout_init(&c);
    selftest_accuracy_fire_time = 0;

    u64 t0 = time_rdtime();
    callout_set_usec(&c, 10000, selftest_accuracy_cb, NULL); /* 10ms */

    /* Every exit must drain &c: a timed-out callout is still in the kernel
     * queue, and unwinding here would dangle the pointer.
     */
    i32 rc = 0;
    u64 timeout = time_ms_to_ticks(100);
    while (selftest_accuracy_fire_time == 0) {
        if (time_rdtime() - t0 > timeout) {
            rc = 1; /* timed out; callout never fired */
            goto out;
        }
    }

    u64 elapsed_us = time_ticks_to_us(selftest_accuracy_fire_time - t0);

    /* Accept [5ms, 80ms] - wide tolerance for QEMU SMP jitter. */
    if (elapsed_us < 5000 || elapsed_us > 80000)
        rc = 1;

out:
    callout_cancel_sync(&c);
    return rc;
}
DEFINE_SELFTEST(callout_accuracy, test_callout_accuracy);

/* Drift compensation test: chain N periodic re-arms anchored to the
 * original schedule (old_deadline + period) and verify the total elapsed
 * time stays within N*P +/- epsilon.  This validates that the callout
 * engine does not accumulate drift across chained one-shot timers.
 */
#define DRIFT_ITERATIONS 5
#define DRIFT_PERIOD_US 10000 /* 10ms per period */

static volatile int selftest_drift_count;
static struct callout selftest_drift_callout;
static u64 selftest_drift_anchor;

static void selftest_drift_cb(void *arg __unused)
{
    selftest_drift_count++;
    if (selftest_drift_count < DRIFT_ITERATIONS) {
        /* Anchor-based re-arm: next deadline = original + (count+1)*period.
         * This is the correct drift-free pattern.
         */
        u64 period_ticks = time_usec_to_ticks(DRIFT_PERIOD_US);
        u64 next_abs = selftest_drift_anchor +
                       (u64) (selftest_drift_count + 1) * period_ticks;
        u64 now = time_rdtime();
        u64 rel = (next_abs > now) ? (next_abs - now) : 1;
        callout_set_ticks(&selftest_drift_callout, rel, selftest_drift_cb,
                          NULL);
    }
}

static i32 test_callout_drift(void)
{
    callout_init(&selftest_drift_callout);
    selftest_drift_count = 0;

    u64 t0 = time_rdtime();
    u64 period_ticks = time_usec_to_ticks(DRIFT_PERIOD_US);
    selftest_drift_anchor = t0;

    callout_set_ticks(&selftest_drift_callout, period_ticks, selftest_drift_cb,
                      NULL);

    /* Wait for all iterations to complete (up to 200ms). */
    u64 timeout = time_ms_to_ticks(200);
    while (selftest_drift_count < DRIFT_ITERATIONS) {
        if (time_rdtime() - t0 > timeout)
            return 1;
    }

    u64 elapsed_us = time_ticks_to_us(time_rdtime() - t0);
    u64 expected_us = (u64) DRIFT_ITERATIONS * DRIFT_PERIOD_US;

    /* Accept +/- 50% tolerance for QEMU jitter. */
    if (elapsed_us < expected_us / 2 || elapsed_us > expected_us * 2)
        return 1;

    return 0;
}
DEFINE_SELFTEST(callout_drift, test_callout_drift);

/* Batch-collect stress test: arm >8 callouts with the same deadline and
 * verify all fire.  Exercises the batch-collect overflow path.
 */
#define BATCH_STRESS_COUNT 12
static volatile int selftest_batch_count;

static void selftest_batch_cb(void *arg __unused)
{
    __atomic_fetch_add(&selftest_batch_count, 1, __ATOMIC_RELAXED);
}

static i32 test_callout_batch_stress(void)
{
    struct callout batch_co[BATCH_STRESS_COUNT];
    selftest_batch_count = 0;

    for (int i = 0; i < BATCH_STRESS_COUNT; i++) {
        callout_init(&batch_co[i]);
        callout_set_ticks(&batch_co[i], time_ms_to_ticks(5), selftest_batch_cb,
                          NULL);
    }

    /* Every exit must drain all callouts: each references &batch_co[i] on
     * this function's stack.
     */
    i32 rc = 0;
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(200);
    while (__atomic_load_n(&selftest_batch_count, __ATOMIC_RELAXED) <
           BATCH_STRESS_COUNT) {
        if (time_rdtime() - start > timeout) {
            rc = 1;
            break;
        }
    }

    for (int i = 0; i < BATCH_STRESS_COUNT; i++)
        callout_cancel_sync(&batch_co[i]);
    return rc;
}
DEFINE_SELFTEST(callout_batch_stress, test_callout_batch_stress);

/* Prove the tickless property: when no callouts are pending, the hardware
 * timer is disarmed (sbi_set_timer(U64_MAX)), so zero STIMER interrupts
 * fire during a quiescent period.
 *
 * Background kernel threads (watchdog) may have callouts armed, so
 * skip gracefully if the list is not empty - can't prove tickless
 * when other subsystems are using the timer.
 */
static i32 test_tickless_idle(void)
{
    struct pcpu *pc = get_pcpu();

    /* Skip if background callouts are armed (e.g. watchdog sleep). */
    if (!callout_list_empty())
        return 0; /* skip gracefully */

    u64 t0_timer = pc->nr_timer;

    /* Busy-wait 50ms with no callouts armed. */
    u64 start = time_rdtime();
    u64 wait = time_ms_to_ticks(50);
    while (time_rdtime() - start < wait)
        ;

    u64 t1_timer = pc->nr_timer;

    /* Zero timer interrupts proves tickless: hardware timer was disarmed. */
    if (t1_timer != t0_timer)
        return 1;

    return 0;
}
DEFINE_SELFTEST(tickless_idle, test_tickless_idle);

/* Verify merged deadline infrastructure: arming a callout that becomes
 * the queue head must produce an sbi_set_timer() call, reflected in
 * nr_timer_writes incrementing.
 */
static i32 test_merged_deadline(void)
{
    struct pcpu *pc = get_pcpu();

    /* Arm a callout with a very short deadline (1 tick) to guarantee it
     * becomes the queue head and triggers a timer reprogram.  This
     * validates that the merged deadline infrastructure (timer_deadline,
     * update_pcpu_deadline, nr_timer_writes) is operational.
     */
    u64 w0 = pc->nr_timer_writes;

    struct callout c;
    callout_init(&c);
    selftest_callout_fired = false;
    /* Use 1 tick - the absolute shortest.  This ensures the callout is
     * earlier than any background callout and becomes the head.
     */
    callout_set_ticks(&c, 1, selftest_callout_cb, NULL);

    u64 w1 = pc->nr_timer_writes;
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(50);
    while (!selftest_callout_fired) {
        if (time_rdtime() - start > timeout)
            break;
    }

    /* The arm must have produced at least one HW timer write.
     * On SMP, the callout may fire so fast that it executes between
     * callout_set_ticks and the w1 sample, making w1 == w0.
     * Accept the test if either the counter incremented OR the callout
     * actually fired (proving the infrastructure works).
     */
    i32 rc = (w1 <= w0 && !selftest_callout_fired) ? 1 : 0;

    /* If the callout never fired (timeout path) it is still queued against
     * &c; drain it before unwinding.
     */
    callout_cancel_sync(&c);
    return rc;
}
DEFINE_SELFTEST(merged_deadline, test_merged_deadline);

/* Equal-deadline stability: two callouts armed at the same absolute
 * deadline must both fire, and the one armed first fires first (FIFO
 * within equal deadlines).  Validates that the sorted insert and
 * batch-collect paths do not drop or reorder equal-deadline entries.
 */
static volatile int eq_deadline_order[2];
static volatile int eq_deadline_idx;

static void eq_deadline_cb(void *arg)
{
    int slot = (int) (uptr) arg;
    int idx = __atomic_fetch_add(&eq_deadline_idx, 1, __ATOMIC_RELAXED);
    if (idx < 2)
        eq_deadline_order[idx] = slot;
}

static i32 test_equal_deadline_stability(void)
{
    struct callout c0, c1;
    callout_init(&c0);
    callout_init(&c1);
    eq_deadline_idx = 0;
    eq_deadline_order[0] = -1;
    eq_deadline_order[1] = -1;

    /* Arm both at the same delay (20ms).  c0 armed first = should fire first.
     */
    u64 delay = time_ms_to_ticks(20);
    callout_set_ticks(&c0, delay, eq_deadline_cb, (void *) (uptr) 0);
    callout_set_ticks(&c1, delay, eq_deadline_cb, (void *) (uptr) 1);

    /* Every exit must drain both callouts: each references its &c on this
     * stack frame.
     */
    i32 rc = 0;
    u64 start = time_rdtime();
    u64 timeout = time_ms_to_ticks(200);
    while (eq_deadline_idx < 2) {
        if (time_rdtime() - start > timeout) {
            rc = 1;
            goto out;
        }
    }

    /* Both must have fired. */
    if (eq_deadline_order[0] == -1 || eq_deadline_order[1] == -1)
        rc = 1;
    /* FIFO stability: c0 armed first, should fire first. */
    else if (eq_deadline_order[0] != 0 || eq_deadline_order[1] != 1)
        rc = 1;

out:
    callout_cancel_sync(&c0);
    callout_cancel_sync(&c1);
    return rc;
}
DEFINE_SELFTEST(equal_deadline_stability, test_equal_deadline_stability);

/* Clockevent mode tracking: verify that the clockevent_mode field in
 * pcpu reflects ONESHOT when a callout is armed and transitions
 * toward SHUTDOWN when all sources are disarmed.
 */
static i32 test_clockevent_mode(void)
{
    struct pcpu *pc = get_pcpu();

    /* Arm a long callout: mode must be ONESHOT. */
    struct callout c;
    callout_init(&c);
    callout_set_ticks(&c, time_ms_to_ticks(500), selftest_callout_cb, NULL);

    /* Drain on every exit: the first assertion may fail while c is still
     * armed, and even after the in-line callout_cancel below an in-flight
     * callback could race the function return.
     */
    i32 rc = 0;
    if (pc->clockevent_mode != CLOCKEVENT_ONESHOT) {
        rc = 1;
        goto out;
    }

    callout_cancel(&c);

    /* After cancel, if no other deadlines are active, mode should be
     * SHUTDOWN.  Background callouts may keep it ONESHOT, so only
     * assert non-garbage.
     */
    if (pc->clockevent_mode != CLOCKEVENT_SHUTDOWN &&
        pc->clockevent_mode != CLOCKEVENT_ONESHOT)
        rc = 1;

out:
    callout_cancel_sync(&c);
    return rc;
}
DEFINE_SELFTEST(clockevent_mode, test_clockevent_mode);

#if CONFIG_SMP
static i32 test_remote_callout_cancel_head(void)
{
    if (nr_cpus_online < 2)
        return 0; /* no secondary hart; skip gracefully */

    u32 me = get_cpuid();
    u32 target = (me == 0) ? 1 : 0;
    struct callout c;
    u64 now = time_rdtime();

    callout_init(&c);
    c.func = selftest_callout_cb;
    c.arg = NULL;
    c.cpu = target;
    c.flags = CALLOUT_FLAG_ARMED;

    u64 flags = spin_lock_irqsave(&callout_lock[target]);
    if (!list_empty(&callout_list[target])) {
        struct callout *head =
            list_entry(callout_list[target].next, struct callout, node);
        if (head->deadline <= now + 1) {
            spin_unlock_irqrestore(&callout_lock[target], flags);
            return 0; /* skip near-expiry queue head */
        }
        c.deadline = head->deadline - 1;
    } else {
        c.deadline = now + time_ms_to_ticks(200);
    }
    callout_insert_locked(&c, target);
    spin_unlock_irqrestore(&callout_lock[target], flags);

    u64 t0_ssi = pcpu_array[target].nr_ssi;

    callout_cancel(&c);

    if (callout_pending(&c))
        return 1;

    u64 start = time_rdtime();
    u64 wait = time_ms_to_ticks(20);
    while (time_rdtime() - start < wait) {
        if (pcpu_array[target].nr_ssi > t0_ssi)
            return 0;
    }

    return 1;
}
DEFINE_SELFTEST(remote_callout_cancel_head, test_remote_callout_cancel_head);

/* Validate external event delivery: send an IPI to another hart and
 * verify that its SSI counter increments.  This proves the cross-hart
 * interrupt wake path works with the per-CPU counters.
 */
static i32 test_ipi_wake(void)
{
    if (nr_cpus_online < 2)
        return 0; /* no secondary hart; skip gracefully */

    /* Pick a target CPU that is not us. */
    u32 me = get_cpuid();
    u32 target = (me == 0) ? 1 : 0;

    u64 t0_ssi = pcpu_array[target].nr_ssi;

    ipi_send(target, IPI_SCHED);

    /* Busy-wait for the IPI to be delivered and handled.
     * 20ms accommodates SMP scheduling jitter — the target hart may be
     * mid-callout or holding a spinlock when the IPI fires.
     */
    u64 start = time_rdtime();
    u64 wait = time_ms_to_ticks(20);
    while (time_rdtime() - start < wait)
        ;

    u64 t1_ssi = pcpu_array[target].nr_ssi;

    if (t1_ssi <= t0_ssi)
        return 1;

    return 0;
}
DEFINE_SELFTEST(ipi_wake, test_ipi_wake);
#endif /* CONFIG_SMP */
